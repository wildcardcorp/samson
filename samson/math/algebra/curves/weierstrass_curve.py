from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.polynomial import Polynomial
from samson.math.factorization.general import factor
from samson.math.algebra.curves.util import EllipticCurveCardAlg
from samson.math.general import pohlig_hellman, mod_inv, schoofs_algorithm, gcd, hasse_frobenius_trace_interval, bsgs, product, crt
from samson.utilities.exceptions import NoSolutionException, SearchspaceExhaustedException
from samson.utilities.runtime import RUNTIME
from functools import lru_cache


class WeierstrassPoint(RingElement):
    """
    Point on a Weierstrass curve.
    """

    def __init__(self, x: int, y: int, curve: 'WeierstrassCurve'):
        self.x     = curve.ring.coerce(x)
        self.y     = curve.ring.coerce(y)
        self.curve = curve
        self.order_cache  = None
        self.result_cache = {}


    def __reprdir__(self):
        return ['x', 'y', 'curve']


    def shorthand(self) -> str:
        return f'{self.curve.shorthand()}({{x={self.x}, y={self.y}}})'


    @property
    def ring(self):
        return self.curve


    @property
    def val(self):
        return self.x



    def __hash__(self):
        return hash(self.curve) ^ hash(self.x) ^ hash(self.y)


    def __int__(self) -> int:
        return int(self.x)


    def __eq__(self, P2: 'WeierstrassPoint') -> bool:
        return self.curve == P2.curve and self.x == P2.x and self.y == P2.y


    def __lt__(self, other: 'WeierstrassPoint') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.x < other.x


    def __gt__(self, other: 'WeierstrassPoint') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.x > other.x


    def __neg__(self) -> 'WeierstrassPoint':
        return WeierstrassPoint(self.x, -self.y, self.curve)


    def __add__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        if self == self.curve.POINT_AT_INFINITY:
            return P2

        if P2 == self.curve.POINT_AT_INFINITY:
            return self

        if self == -P2:
            return self.curve.POINT_AT_INFINITY

        if self == P2:
            m = (3*self.x**2 + self.curve.a) / (2 * self.y)
        else:
            m = (P2.y - self.y) / (P2.x - self.x)

        x = m**2 - self.x - P2.x
        y = m * (self.x - x) - self.y

        return WeierstrassPoint(x, y, self.curve)


    def __radd__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        return self.__add__(P2)


    def __sub__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        return self + (-P2)


    def __rsub__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        return -self + P2


    def __truediv__(self, other: 'WeierstrassPoint') -> 'WeierstrassPoint':
        if type(other) is int:
            return self*mod_inv(other, self.curve.q)

        else:
            E        = self.ring
            P        = E(other)
            ord_facs = factor(P.order)
            F        = E.ring

            # Check if we can do the MOV attack
            if RUNTIME.enable_MOV_attack:
                k = E.embedding_degree

                # Is it even economical?
                if k < 7 and max(ord_facs).bit_length() > RUNTIME.index_calculus_supremacy:
                    from samson.math.algebra.fields.finite_field import FiniteField as GF
                    K  = GF(int(F.quotient), k)
                    E_ = WeierstrassCurve(K(E.a), K(E.b))
                    Q  = self

                    # Implementation detail: Elliptic curve operations faster than
                    # poly mul/div, so only do index calculus on large groups
                    large_facs     = {p: e for p,e in ord_facs.items() if p.bit_length() > RUNTIME.index_calculus_supremacy}
                    small_facs     = ord_facs - large_facs
                    large_facs     = ord_facs - small_facs
                    large_subgroup = product([p**e for p,e in large_facs.items()])
                    small_subgroup = P.order // large_subgroup


                    res = pohlig_hellman(P * large_subgroup, Q * large_subgroup, factors=small_facs)

                    if res * P == Q:
                        return res

                    Km = K.mul_group()

                    # Confine points to the large subgroup
                    Qp = Q * small_subgroup
                    Pp = P * small_subgroup

                    P_ = E_(Pp.x, Pp.y)
                    Q_ = E_(Qp.x, Qp.y)

                    while True:
                        # Find a random point of `n`-torsion
                        g  = E_.find_element_of_order(P.order, ord_facs)
                        R  = g * small_subgroup
                        W2 = Q_.weil_pairing(R, large_subgroup)

                        # Make sure it generates the whole group
                        if Km(W2).order == large_subgroup:
                            break

                    W1 = P_.weil_pairing(R, large_subgroup)

                    return crt([(W2.log(W1), large_subgroup), (res, small_subgroup)])[0]

            return pohlig_hellman(P, self, factors=ord_facs)


    __floordiv__ = __truediv__


    def line(self, R: 'WeierstrassPoint', Q: 'WeierstrassPoint') -> 'RingElement':
        """
        References:
            https://github.com/sagemath/sage/blob/develop/src/sage/schemes/elliptic_curves/ell_point.py#L1270
        """
        if not Q:
            raise ValueError("'Q' cannot be zero")

        if not self or not R:
            if self == R:
                return self.ring.ring.one
            if R:
                return Q.x - R.x
            else:
                return Q.x - self.x

        elif self != R:
            if self.x == R.x:
                return Q.x - self.x
            else:
                l = (R.y - self.y) / (R.x - self.x)
                return Q.y - self.y - l * (Q.x - self.x)

        else:
            den = (2*self.y)

            if not den:
                return Q.x - self.x
            else:
                l = (3*self.x**2 + self.ring.a)/den
                return Q.y - self.y - l * (Q.x - self.x)



    def miller(self, Q: 'WeierstrassPoint', n: int) -> 'RingElement':
        """
        References:
            https://github.com/sagemath/sage/blob/develop/src/sage/schemes/elliptic_curves/ell_point.py#L1345
        """
        if not Q:
            raise ValueError("'Q' cannot be zero")

        if not n:
            raise ValueError("'n' cannot be zero")

        # Handle negatives later
        is_neg = False

        if n < 0:
           n = abs(n)
           is_neg = True

        t = self.ring.ring.one
        V = self

        # Double and add
        for bit in [int(bit) for bit in bin(n)[3:]]:
            S = 2*V
            l = V.line(V, Q)
            v = S.line(-S, Q)
            t = (t**2)*(l/v)
            V = S

            if bit:
                S = V+self
                l = V.line(self, Q)
                v = S.line(-S, Q)
                t = t*(l/v)
                V = S


        if is_neg:
            v = V.line(-V, Q)
            t = ~(t*v)

        return t


    def weil_pairing(self, Q: 'WeierstrassPoint', n: int) -> 'RingElement':
        """
        References:
            https://github.com/sagemath/sage/blob/develop/src/sage/schemes/elliptic_curves/ell_point.py#L1520
        """
        E = self.ring

        if not Q in E:
            raise ValueError(f"Q: {Q} is not on {E}")

        # Ensure P and Q are both in E[n]
        if n*self:
            raise ValueError(f"self: {self} is not {n}-torsion")

        if n*Q:
            raise ValueError(f"Q: {Q} is not {n}-torsion")

        one = E.ring.one

        if self == Q:
            return one

        if not self or not Q:
            return one

        try:
            res = self.miller(Q, n) / Q.miller(self, n)

            if n % 2:
                res = -res

            return res

        except ZeroDivisionError:
            return one




class PointAtInfinity(WeierstrassPoint):
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve


    def __reprdir__(self):
        return ['curve']


    def __eq__(self, P2: 'WeierstrassPoint') -> bool:
        return self is P2


    def __hash__(self):
        return object.__hash__(self)


    def __neg__(self) -> 'WeierstrassPoint':
        return self



class WeierstrassCurve(Ring):
    """
    Elliptic curve of form y**2 = x**3 + a*x + b
    """

    def __init__(self, a: RingElement, b: RingElement, ring: Ring=None, base_tuple: tuple=None, cardinality: int=None, check_singularity: bool=True):
        """
        Parameters:
            a          (RingElement): `a` coefficient.
            b          (RingElement): `b` constant.
            ring              (Ring): Underlying ring.
            base_tuple       (tuple): Tuple representing the base point 'G'.
            cardinality        (int): Number of points on the curve.
            check_singularity (bool): Check if the curve is singular (no cusps or self-intersections).
        """
        from samson.math.symbols import Symbol

        self.ring = ring or a.ring
        self.a  = self.ring(a)
        self.b  = self.ring(b)


        if check_singularity:
            if (4 * a**3 + 27 * b**2) == self.ring.zero:
                raise ValueError("Elliptic curve can't be singular")

        if base_tuple:
            base_tuple = WeierstrassPoint(*base_tuple, self)

        self.G_cache     = base_tuple
        self.PAF_cache   = None
        self.dpoly_cache = {}

        self.cardinality_cache = cardinality
        self.curve_poly_ring   = self[Symbol('x'), Symbol('y')]

        self.zero = PointAtInfinity(self.ring.zero, self.ring.zero, self)



    def __reprdir__(self):
        return ['a', 'b', 'cardinality_cache', 'ring']



    def shorthand(self) -> str:
        return f'WeierstrassCurve{{a={self.a}, b={self.b}}}'


    def __getitem__(self, args):
        from samson.math.algebra.rings.curve_polynomial_ring import CurvePolynomialRing
        if type(args) is tuple:
            return CurvePolynomialRing(self.ring[args[0]], self.a, self.b)
        else:
            return super().__getitem__(args)


    def coerce(self, x: 'RingElement', y: 'RingElement'=None) -> WeierstrassPoint:
        if type(x) is WeierstrassPoint:
            if x.curve == self:
                return x
            else:
                return self(x.x, x.y)

        if y is not None:
            return WeierstrassPoint(x, y, self)
        else:
            return self.recover_point_from_x(x)


    def __call__(self, x: 'RingElement', y: 'RingElement'=None) -> WeierstrassPoint:
        return self.coerce(x, y)


    def __eq__(self, other: 'WeierstrassCurve') -> bool:
        return type(other) == type(self) and self.a == other.a and self.b == other.b


    def __hash__(self):
        return hash((self.a, self.b))


    def __deepcopy__(self, memo):
        result = WeierstrassCurve(a=self.a, b=self.b, ring=self.ring, base_tuple=(self.G.x, self.G.y), cardinality=self.cardinality_cache)
        memo[id(self)] = result
        return result


    @property
    def p(self) -> int:
        return int(self.ring.quotient)


    @staticmethod
    def random_curve(n: RingElement) -> 'WeierstrassCurve':
        R = n.ring
        ring = R/n

        while True:
            x = R.random(n)
            y = R.random(n)
            a = R.random(n)
            b = (y**2 - x**3 - (a * x))

            g = gcd(int(4 * a**3 - 27 * b**2), n)
            if g != n:
                break

        curve = WeierstrassCurve(a=a, b=b, ring=ring, base_tuple=(x, y))
        return curve, g


    def cardinality(self, algorithm: EllipticCurveCardAlg=EllipticCurveCardAlg.AUTO) -> int:
        """
        Calculates the cardinality (number of points) of the curve and caches the result.

        Parameters:
            algorithm (EllipticCurveCardAlg): Algorithm to use.

        Returns:
            int: Cardinality of the curve.
        """
        if not self.cardinality_cache:
            p = self.ring.order
            if algorithm == EllipticCurveCardAlg.AUTO:
                curve_size = p.bit_length()

                if curve_size < 6:
                    algorithm = EllipticCurveCardAlg.BRUTE_FORCE
                elif curve_size <= 96:
                    algorithm = EllipticCurveCardAlg.BSGS
                else:
                    algorithm = EllipticCurveCardAlg.SCHOOFS


            if algorithm == EllipticCurveCardAlg.BRUTE_FORCE:
                start, end = hasse_frobenius_trace_interval(p)
                order      = 1

                for _ in range(p):
                    po    = bsgs(self.random(), self.zero, e=self.zero, start=start + p, end=end + p)
                    order = max(order, po)

                self.cardinality_cache = order

            elif algorithm == EllipticCurveCardAlg.BSGS:
                # This is pretty slick. The order is at minimum `p - 2*sqrt(p)`. For p > 43, `2 * (p - 2*sqrt(p))`
                # is always outside of the interval. This means if we find a point with an order
                # greater than or equal to `(p - 2*sqrt(p))`, that has to be the order of the curve.
                # Additionally, due to Langrange's theorem, every element's order is a divisor of
                # the group's order. If we only search inside of the interval, and the element's
                # order is greater than the interval, then the discrete logarithm of the point
                # at infinity will be the curve's order
                start, end = hasse_frobenius_trace_interval(p)
                while True:
                    try:
                        g = self.random()
                        bsgs(g, self.zero, e=self.zero, start=1, end=end-start)
                    except SearchspaceExhaustedException:
                        break

                order = bsgs(g, self.zero, e=self.zero, start=start + p, end=end + p)

                self.cardinality_cache = order

            elif algorithm == EllipticCurveCardAlg.SCHOOFS:
                self.cardinality_cache = schoofs_algorithm(self)

            else:
                raise ValueError(f"Unkown EllipticCurveCardAlg '{algorithm}'")

        return self.cardinality_cache


    @property
    def j_invariant(self) -> 'RingElement':
        """
        References:
            https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange#Background
        """
        R  = self.ring
        a3 = R(self.a)**3
        return 1728*((4*a3)/(4*a3 + 27*R(self.b)**2))


    @property
    def is_supersingular(self):
        """
        References:
            https://en.wikipedia.org/wiki/Supersingular_elliptic_curve#Definition
            "Elliptic Curves: Number Theory and Cryptography, 4.37" (https://people.cs.nctu.edu.tw/~rjchen/ECC2012S/Elliptic%20Curves%20Number%20Theory%20And%20Cryptography%202n.pdf)
        """
        R = self.ring
        p = R.characteristic
        j = self.j_invariant

        if p % 3 == 2:
            return j == R(0)

        elif p % 4 == 3:
            return j == R(1728)

        else:
            return self.cardinality() % p == 1


    @property
    @lru_cache(1)
    def embedding_degree(self):
        from samson.math.algebra.rings.integer_ring import ZZ

        Fo = self.ring.order
        Eo = self.order

        Zem = (ZZ/ZZ(Eo)).mul_group()
        return Zem(Fo).order


    @property
    def trace_of_frobenius(self) -> int:
        return self.ring.order + 1 - self.cardinality()


    trace = trace_of_frobenius

    @property
    def q(self) -> int:
        return self.cardinality()


    @property
    def order(self) -> int:
        return self.cardinality()


    @property
    def characteristic(self) -> int:
        return self.G.order


    @property
    def G(self) -> WeierstrassPoint:
        if not self.G_cache:
            self.G_cache = self.find_gen()

        return self.G_cache


    @property
    def one(self):
        return self.G


    @property
    def POINT_AT_INFINITY(self) -> WeierstrassPoint:
        if not self.PAF_cache:
            self.PAF_cache = self.zero

        return self.PAF_cache


    @property
    @lru_cache(1)
    def cm_discriminant(self) -> int:
        """
        References:
            https://safecurves.cr.yp.to/disc.html
        """
        from samson.math.factorization.general import factor
        from samson.math.factorization.factors import Factors
        t = self.trace
        p = self.ring.characteristic
        d = t**2-4*p

        facs = factor(d)
        s    = Factors({p: e // 2 for p,e in facs.items()})
        D    = d // s.recombine()**2

        if D % 4 != 1:
            D *= 4

        return D



    @staticmethod
    def from_j(j: RingElement) -> 'WeierstrassCurve':
        R = j.ring
        if j == R.zero:
            a, b = R.zero, R.one

        elif j == R(1728):
            a, b = R.one, R.zero

        else:
            k    = j-1728
            a, b = -3*j*k, -2*j*k**2

        return WeierstrassCurve(a, b)


    def quadratic_twist(self, D: int=None) -> 'WeierstrassCurve':
        R = self.ring
        p = R.characteristic

        if D is None:
            while True:
                D = R.random()
                if not D.is_square():
                    break

        b4, b6 = 2*self.a, 4*self.b
        twist  = WeierstrassCurve(8*b4*D**2, 16*b6*D**3)

        if self.cardinality_cache:
            twist.cardinality_cache = 2*p+2-self.order

        return twist



    @staticmethod
    def generate_curve_with_trace(bit_size: int, trace: int) -> 'EllipticCurve':
        """
        Generates an `EllipticCurve` with field size `bit_size` and trace `trace`.

        Parameters:
            bit_size (int): Size of the underlying finite field in bits.
            trace    (int): Trace curve should have.

        Returns:
            EllipticCurve: Constructed curve.
        """
        hasse_range = hasse_frobenius_trace_interval(2**bit_size)

        if trace not in range(*hasse_range):
            raise ValueError(f"Trace {trace} not within Hasse bounds {hasse_range} for bit_size {bit_size}")

        if trace % 2:
            return EllipticCurve._generate_curve_with_odd_trace(bit_size, trace)
        elif not trace:
            return EllipticCurve._generate_supersingular(bit_size)
        else:
            return EllipticCurve._generate_curve_with_even_trace(bit_size, trace)



    @staticmethod
    def _generate_supersingular(bit_size: int=None, p:int=None) -> 'EllipticCurve':
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.prime_gen import PrimeEngine

        if not (bit_size or p):
            raise ValueError("Either 'bit_size' or 'p' must be specified")

        p = p or PrimeEngine.GENS.RANDOM(bit_size).generate([lambda p: p % 4 == 3])

        R = ZZ/ZZ(p)
        a = R.random()

        while not a.is_square():
            a = R.random()

        E = EllipticCurve(a, R.zero)
        E.cardinality_cache = p + 1
        return E


    @staticmethod
    def _generate_curve_with_odd_trace(bit_size: int, trace: int) -> 'EllipticCurve':
        """
        References:
            "Generating Anomalous Elliptic Curves" (http://www.monnerat.info/publications/anomalous.pdf)
        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.general import random_int_between, is_prime, kth_root

        if not trace % 2:
            raise ValueError("Algorithm can only generate curves with odd trace")


        # Prime D's congruent to 3 % 8
        # Sage code to generate:

        # D_MAP = {}
        # for i in range(1, 10000):
        #     D = -(3+8*i)
        #     if is_prime(-D):
        #         roots = hilbert_class_polynomial(D).roots()
        #         if roots:
        #             D_MAP[D] = roots[0][0]


        D_MAP = {
            11: -2**15,
            19: -2**15*3**3,
            43: -2**18*3**3*5**3,
            67: -2**15*3**3*5**3*11**3,
            163: -2**18*3**3*5**3*23**3*29**3,
        }

        valid_Ds = [D for D in D_MAP if trace % D]

        if not valid_Ds:
            raise ValueError("Odd trace algorithm doesn't work with traces that are multiples of 98147027")


        D      = valid_Ds[0]
        j      = D_MAP[D]
        m_size = (2**bit_size // D).bit_length() // 2

        # Find a prime such that 4p = x^2 + Dy^2, and x=trace
        # This construction will force the trace to be +-x
        while True:
            m = random_int_between(2**(m_size-1), 2**m_size)
            p = D*m*(m+1) + (D + trace**2) // 4

            if p.bit_length() == bit_size and is_prime(p) and not (4*p - trace**2) % D:
                y2 = (4*p - trace**2) // D
                y = kth_root(y2, 2)
                if y**2 == y2:
                    break

        R = ZZ/ZZ(p)


        # If the cardinality is incorrect, then the twist is the right one
        E = EllipticCurve.from_j(R(j))
        P = E.random()
        if P*(p+1-trace):
            E = E.quadratic_twist()

        E.cardinality_cache = p+1-trace
        return E


    @staticmethod
    def _generate_curve_with_even_trace(bit_size: int, trace: int) -> 'EllipticCurve':
        """
        References:
            "ELLIPTIC CURVES OF NEARLY PRIME ORDER." (https://eprint.iacr.org/2020/001.pdf)
        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.general import random_int, is_prime

        def build_curve(p, a, negate):
            R   = ZZ/ZZ(p)
            o   = p + 1 - a*2
            mod = -negate*2 + 1
            E   = EllipticCurve(R(mod*a), R(0))

            if E.random()*o:
                return None

            else:
                E.cardinality_cache = o
                return E


        if trace % 2:
            raise ValueError("Even trace algorithm can only generate curves with even trace")


        if not trace % 8:
            raise ValueError("Even trace algorithm can't generate traces that are multiples of 8")


        # The algorithm fails if trace is negative
        # Instead, remove the negative and return the twist at the end
        neg_trace = False
        if trace < 0:
            trace     = -trace
            neg_trace = True


        # TODO: Why? I really don't know
        if trace % 48 == 42:
            raise ValueError("Even trace algorithm can't generate traces that are 42 mod 48 (absolute value)")


        # p must be 5 % 8
        # If a is odd, then b should be even
        a      = trace // 2
        b_size = (2**bit_size - a**2).bit_length() // 2
        b      = 2**(b_size-1) + 2**(b_size-2) - random_int(2**(b_size-5))*2 + ((a+1) % 2)
        max_b  = 2**b_size

        E = None
        while b < max_b:
            b += 2
            p  = a**2 + b**2
            if is_prime(p):
                pdash = (p-3) // 2

                if is_prime(pdash):
                    E = build_curve(p, a, False)


                pbar = (p+5) // 2
                if is_prime(pbar):
                    E = build_curve(p, a, True)


                if E:
                    if neg_trace:
                        E = E.quadratic_twist()
                    return E


        raise SearchspaceExhaustedException



    @staticmethod
    def generate_curve_with_order(order: int, max_r: int=20) -> 'EllipticCurve':
        """
        Generates the curve with the prescribed order.

        Parameters:
            order (int): Order of the curve to generate.

        Returns:
            EllipticCurve: Generated curve.

        References:
            "Constructing elliptic curves of prime order" (http://www.math.leidenuniv.nl/~psh/bs.pdf)
        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.symbols import Symbol
        from samson.math.general import hilbert_class_polynomial, cornacchias_algorithm, primes, is_prime

        def construct_prime(N: int, max_r: int):
            from samson.math.factorization.factors import Factors
            from math import log2

            logN = int(log2(N))
            Zn   = ZZ/ZZ(N)

            for r in range(max_r):
                S  = {}

                op = [p for p in primes(max(r*logN, 3), (r+1)*logN) if (ZZ/ZZ(p))(N).is_square()]
                S  = [Zn(p) for p in op if Zn(p).is_square()]

                fac = Factors({p:1 for p in S})
                for i in range(1, len(S)+1):
                    for l in fac.combinations(i):
                        D = int(l.recombine())

                        if -D % 8 == 5:
                            try:
                                t, _ = cornacchias_algorithm(D, 4*N, use_hensel=True)

                                prime = N + 1 + t
                                if is_prime(prime):
                                    return D, prime

                                prime = N + 1 - t
                                if is_prime(prime):
                                    return D, prime
                            except NoSolutionException:
                                pass
            
            raise NoSolutionException

        # Find suitable prime and discriminant
        D, p = construct_prime(order, max_r)
        Zp   = ZZ/ZZ(p)
        Z    = Zp[Symbol('x')]

        # Find j-invariant
        hd = hilbert_class_polynomial(D)
        r  = Z(hd).roots()[0]
        E  = EllipticCurve.from_j(r)

        # Either this curve or the twist has the correct order
        if E.random()*order:
            E = E.quadratic_twist()

        E.cardinality_cache = order
        return E



    def to_montgomery_form(self) -> 'WeierstrassCurve':
        """
        References:
            https://en.wikipedia.org/wiki/Montgomery_curve#Equivalence_with_Weierstrass_curves
        """
        from samson.math.symbols import Symbol
        from samson.math.algebra.curves.montgomery_curve import MontgomeryCurve

        # Order nust be divisible by 4
        if self.order % 4:
            raise NoSolutionException("Order must be divisible by 4")


        z = Symbol('z')
        _ = self.ring[z]

        # Curve equation must have roots
        roots = (z**3 + self.a*z + self.b).roots()

        if not roots:
            raise NoSolutionException("Curve equation has no roots")


        # Derivative at root must be a square
        for alpha in roots:
            delta = 3*alpha**2 + self.a

            if not delta.is_square():
                continue

            s = ~delta.sqrt()

            x, y = s*(self.G.x-alpha), self.G.y*s
            return MontgomeryCurve(A=3*alpha*s, B=s, U=x, V=y, order=self.order)

        raise NoSolutionException("'delta' is not a quadratic residue")


    def element_at(self, x: int) -> WeierstrassPoint:
        """
        Returns the `x`-th element w.r.t to the generator.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           WeierstrassPoint: The `x`-th point.
        """
        return self.G*x


    def recover_point_from_x(self, x: int) -> WeierstrassPoint:
        """
        Uses the curve equation to create a point with x-coordinate `x`.

        Parameters:
            x (int): x-coordinate.
        
        Returns:
            WeierstrassPoint: Point at x-coordinate.
        """
        x = self.ring(x)
        y = (x**3 + self.a*x + self.b).sqrt()
        return WeierstrassPoint(x, y, self)


    def random(self, size: WeierstrassPoint=None) -> WeierstrassPoint:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            WeierstrassPoint: Random element of the algebra.
        """
        while True:
            try:
                return self.recover_point_from_x(self.ring.random())
            except NoSolutionException:
                pass


    def division_poly(self, n: int) -> Polynomial:
        """
        Finds the `n`-th division polynomial.

        Parameters:
            n (int): Index of division polynomial.
        
        Returns:
            Polynomial: Division polynomial of the curve.
        """
        if n in self.dpoly_cache:
            return self.dpoly_cache[n]

        x = self.curve_poly_ring.poly_ring.symbol

        a, b   = self.a, self.b
        d_poly = None

        if n in [0, 1]:
            d_poly = self.curve_poly_ring(n)

        elif n == 2:
            d_poly = self.curve_poly_ring((0, 2))

        elif n == 3:
            d_poly = self.curve_poly_ring(3*x**4 + 6*a*x**2 + 12*b*x - a**2)

        elif n == 4:
            d_poly = self.curve_poly_ring((0, 4*x**6 + 20*a*x**4 + 80*b*x**3 - 20*a**2*x**2 - 16*a*b*x - 4*a**3 - 32*b**2))

        else:
            y   = self.curve_poly_ring((0, 1))
            two = self.curve_poly_ring.poly_ring([2])
            psi = self.division_poly
            for j in range(5, n+1):
                k, m = divmod(j, 2)

                if m:
                    self.dpoly_cache[j] = psi(k+2) * psi(k)**3 - psi(k+1)**3 * psi(k-1)
                else:
                    if k % 2 == 0:
                        self.dpoly_cache[j] = self.curve_poly_ring((psi(k).y_poly // two)) * (psi(k+2) * psi(k-1)**2 - psi(k-2) * psi(k+1)**2)
                    else:
                        self.dpoly_cache[j] = y * (psi(k).x_poly // two) * (psi(k+2) * psi(k-1).y_poly**2 - psi(k-2) * psi(k+1).y_poly**2)

            d_poly = self.dpoly_cache[n]


        self.dpoly_cache[n] = d_poly

        return d_poly


EllipticCurve = WeierstrassCurve
