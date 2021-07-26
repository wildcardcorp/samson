from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.polynomial import Polynomial
from samson.math.factorization.general import factor, is_perfect_power
from samson.math.algebra.curves.util import EllipticCurveCardAlg
from samson.math.general import pohlig_hellman, mod_inv, schoofs_algorithm, gcd, hasse_frobenius_trace_interval, bsgs, product, crt, is_prime, kth_root, batch_inv, lcm, frobenius_trace_mod_l, legendre, cornacchias_algorithm, hilbert_class_polynomial, random_int, random_int_between, find_prime, primes
from samson.math.map import Map
from samson.utilities.exceptions import NoSolutionException, SearchspaceExhaustedException, CoercionException
from samson.utilities.runtime import RUNTIME
import math

from samson.auxiliary.lazy_loader import LazyLoader
_elliptic_curve_isogeny  = LazyLoader('_elliptic_curve_isogeny', globals(), 'samson.math.algebra.curves.elliptic_curve_isogeny')


def _get_possible_traces_for_D(D, N):
    sols = []
    try:
        sols.extend([t for t,_ in cornacchias_algorithm(abs(D), 4*N, use_hensel=True, all_sols=True)])
    except NoSolutionException:
        pass

    try:
        sols.extend([t*2 for t,_ in cornacchias_algorithm(abs(D), N, use_hensel=True, all_sols=True)])
    except NoSolutionException:
        pass

    if not sols:
        raise NoSolutionException
    
    return sols


_D_MAP = [11, 19, 43, 67, 163, 27, 35, 51, 91, 115, 123, 187, 235, 267, 403, 427]


class WeierstrassPoint(RingElement):
    """
    Point on a Weierstrass curve.
    """

    def __init__(self, x: RingElement, y: RingElement, curve: 'WeierstrassCurve', z: RingElement=None):
        self._x    = curve.ring.coerce(x)
        self._y    = curve.ring.coerce(y)
        self._z    = curve.ring.coerce(curve.ring.one if z is None else z)
        self.curve = curve
        self.order_cache  = None


    def __reprdir__(self):
        return ['x', 'y', 'curve']


    def __getitem__(self, idx):
        return [self.x, self.y, self.z][idx]


    def shorthand(self) -> str:
        return f'{self.curve.shorthand()}({{x={self.x}, y={self.y}}})'


    def tinyhand(self) -> str:
        return f'({self.x} : {self.y} : {self.z})'


    @property
    def ring(self):
        return self.curve


    @property
    def val(self):
        return self.x


    def _collapse_coords(self):
        if self._z and self._z != self._x.ring.one:
            z_inv = ~self._z
            self._x *= z_inv
            self._y *= z_inv
            self._z  = self._x.ring.one


    @property
    def x(self):
        self._collapse_coords()
        return self._x

    @property
    def y(self):
        self._collapse_coords()
        return self._y

    @property
    def z(self):
        self._collapse_coords()
        return self._z


    def __hash__(self):
        return hash((self.curve, self.x, self.y))


    def __int__(self) -> int:
        return int(self.x)
    

    def fast_compare_x(self, P2: 'WeierstrassPoint') -> bool:
        return P2._x*self._z == self._x*P2._z


    def fast_compare_y(self, P2: 'WeierstrassPoint') -> bool:
        return P2._y*self._z == self._y*P2._z

    def __eq__(self, P2: 'WeierstrassPoint') -> bool:
        return self.curve == P2.curve and self.fast_compare_x(P2) and self.fast_compare_y(P2)


    def __lt__(self, other: 'WeierstrassPoint') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")
        
        X1, Z1 = self._x, self._z
        X2, Z2 = other._x, other._z
        V1 = X2*Z1
        V2 = X1*Z2

        return V2 < V1


    def __gt__(self, other: 'WeierstrassPoint') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        X1, Z1 = self._x, self._z
        X2, Z2 = other._x, other._z
        V1 = X2*Z1
        V2 = X1*Z2

        return V2 > V1


    def __neg__(self) -> 'WeierstrassPoint':
        return WeierstrassPoint(self._x, -self._y, self.curve, self._z)


    def __double(self):
        if not self._y:
            return self.curve.POINT_AT_INFINITY

        X, Y, Z = self._x, self._y, self._z
        W  = self.curve.a*(Z*Z) + (X*X)*3
        S  = Y*Z
        B  = X*Y*S
        B4 = B*4
        H  = W*W - B4*2
        X_ = H*S*2
        S2 = S*S*8
        Y_ = W*(B4 - H) - (Y*Y)*S2
        Z_ = S*S2

        return WeierstrassPoint(x=X_, y=Y_, z=Z_, curve=self.curve)


    def add_no_cache(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        # https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates
        if self.curve.POINT_AT_INFINITY == P2:
            return self

        elif self.curve.POINT_AT_INFINITY == self:
            return P2

        X1, Y1, Z1 = self._x, self._y, self._z
        X2, Y2, Z2 = P2._x, P2._y, P2._z
        A = self.curve.a

        U1 = Y2*Z1
        U2 = Y1*Z2
        V1 = X2*Z1
        V2 = X1*Z2

        if V1 == V2:
            if U1 == U2:
                return self.__double()
            else:
                return self.curve.POINT_AT_INFINITY

        U  = U1 - U2
        V  = V1 - V2
        W  = Z1*Z2
        VS = V*V
        VT = VS*V
        A  = (U*U)*W - VT - VS*V2*2
        X3 = V*A
        Y3 = U*(VS*V2 - A) - VT*U2
        Z3 = VT*W

        return WeierstrassPoint(x=X3, y=Y3, z=Z3, curve=self.curve)


    def mul_no_cache(self, other: int) -> 'WeierstrassPoint':
        return super().__mul__(other)
                

    @RUNTIME.global_cache()
    def __add__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        return self.add_no_cache(P2)


    def __radd__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        return self.__add__(P2)


    def __sub__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        return self + (-P2)


    def __rsub__(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        return -self + P2


    def __mul__(self, other: int) -> 'WeierstrassPoint':
        result = self.mul_no_cache(other)
        result._collapse_coords()
        return result



    def __truediv__(self, other: 'WeierstrassPoint') -> 'WeierstrassPoint':
        if type(other) is int:
            return self*mod_inv(other, self.order())
        
        elif not other:
            raise ZeroDivisionError
        
        elif not self:
            return 0

        # Is it an anomalous curve? Do additive transfer
        elif not (self * self.ring.ring.characteristic()):
            phi = self.curve.additive_transfer_map()
            return int((phi(self) / phi(other))[0])

        else:
            E        = self.ring
            P        = E(other)
            ord_facs = factor(P.order())

            # Is it even economical?
            if RUNTIME.enable_MOV_attack and max(ord_facs).bit_length() > RUNTIME.index_calculus_supremacy and (E.is_supersingular() or E.embedding_degree() < 7):
                Q = self

                # Implementation detail: Elliptic curve operations faster than
                # poly mul/div, so only do index calculus on large groups
                large_facs     = {p: e for p,e in ord_facs.items() if p.bit_length() > RUNTIME.index_calculus_supremacy}
                small_facs     = ord_facs - large_facs
                large_facs     = ord_facs - small_facs
                large_subgroup = product([p**e for p,e in large_facs.items()])
                small_subgroup = P.order() // large_subgroup


                res = pohlig_hellman(P * large_subgroup, Q * large_subgroup, factors=small_facs)

                if res * P == Q:
                    return res


                # Confine points to the large subgroup
                Qp = Q * small_subgroup
                Pp = P * small_subgroup

                phi = Pp.multiplicative_transfer_map()
                W1  = phi(Pp)
                W2  = phi(Qp)

                return crt([(W2/W1, large_subgroup), (res, small_subgroup)])[0]

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


    def weil_pairing(self, Q: 'WeierstrassPoint', n: int=None) -> 'RingElement':
        """
        References:
            https://github.com/sagemath/sage/blob/develop/src/sage/schemes/elliptic_curves/ell_point.py#L1520
        """
        E = self.ring
        n = n or self.order()

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



    def tate_pairing(self, Q: 'WeierstrassPoint', n: int=None, k :int=None) -> 'RingElement':
        n = n or self.order()
        k = k or self.ring.embedding_degree()
        p = self.ring.ring.characteristic()

        return self.miller(Q, n)**((p**k-1) // n)


    @RUNTIME.global_cache(4)
    def multiplicative_transfer_map(self) -> 'Map':
        """
        Generates a map to `Fq*` such that if `Q` = `self`*`d`, then `phi(Q)` = `phi(self)`*`d`.

        Returns:
            Map: Map function.
        
        Examples:
            >>> from samson.math.algebra.curves.weierstrass_curve import EllipticCurve
            >>> from samson.math.general import random_int
            >>> E = EllipticCurve.generate_curve_with_trace(10, 0)
            >>> E.embedding_degree()
            2

            >>> g = E.G
            >>> d = random_int(E.G.order())
            >>> q = g*d
            >>> M = g.multiplicative_transfer_map()
            >>> M(q)/M(g) == d
            True

        """
        from samson.math.algebra.fields.finite_field import FiniteField as GF
        E = self.curve
        F = E.ring

        k  = E.embedding_degree()
        K  = GF(F.characteristic(), k)
        E_ = WeierstrassCurve(K(E.a), K(E.b))
        Km = K.mul_group()

        P = E_(self)
        o = P.order()

        while True:
            R  = E_.find_element_of_order(o)
            W2 = P.weil_pairing(R, o)

            if Km(W2).order() == o:
                def mul_trans(Q):
                    return Km(E_(Q).weil_pairing(R, o))

                return Map(E, Km, mul_trans)


    def __batch_invert_zs(self, points):
        zeroes = [idx for idx, point in enumerate(points) if not point._z]
        invs   = batch_inv([point._z for point in points if point._z])
        zero   = self._x.ring.zero

        total = 0
        for idx in zeroes:
            invs.insert(idx+total, zero)
            total += 1

        return invs


    @RUNTIME.global_cache(2)
    def _build_bsgs_table(self, g: 'WeierstrassPoint', end: int, start: int, r: int, n: int):
        search_range = end - start
        table        = {}
        y_table      = {}
        m            = kth_root(search_range // n, 2)

        # If we have no congruence, we can apply the involution speedup
        if n == 1:
            # TODO: How to reduce baby steps with involution map?
            # bs_size = max(m // 2, 1)
            bs_size = m
        else:
            bs_size = m

        # Align `e` with congruence
        e = g * ((r-start) % n)
        G = g*n

        # Defer inversions until we can batch them
        points = []
        for i in range(bs_size):
            points.append(e)
            e = e.add_no_cache(G)

        invs = self.__batch_invert_zs(points)

        # Perform inversions then cache
        for i in range(bs_size):
            e = points[i]
            z = invs[i]
            if z:
                e._x, e._y, e._z = e._x*z, e._y*z, e._z*z
            table[e.x]   = i
            y_table[e.x] = e.y

        return table, y_table, m



    def bsgs(self, g: 'WeierstrassPoint', end: int, start: int=0, congruence: tuple=None, e: 'WeierstrassPoint'=None) -> int:
        """
        References:
            "MIT class 18.783, lecture notes #8: Point counting" (https://math.mit.edu/classes/18.783/2019/LectureNotes8.pdf)
            "Computing Elliptic Curve Discrete Logarithms with Improved Baby-step Giant-step Algorithm" (https://eprint.iacr.org/2015/605.pdf)
        """
        h = self
        if congruence:
            r, n = congruence
        else:
            r, n = 0, 1

        # Our BSGS implementation fails for points of order 2 since the point at infinity and our `x`
        # are both zero
        if not g*2:
            d = int(h == g)
            if d >= end or d % n != r:
                raise SearchspaceExhaustedException(f'Discrete log found but does not match parameters: d = {d}')
            else:
                return d

        table, y_table, m = self._build_bsgs_table(g, end, start, r, n)

        mb     = m.bit_length()
        o      = g*start
        factor = -g * (m*n)
        z      = h-o

        for b in range((m+mb-1) // mb):
            points = []
            for i in range(mb):
                points.append(z)
                z = z.add_no_cache(factor)

            invs = self.__batch_invert_zs(points)

            for i, (e, inv) in enumerate(zip(points, invs)):
                x = e._x*inv
                if x in table:
                    baby_idx = table[x]
                    if y_table[x] != e._y*inv:
                        baby_idx = -baby_idx

                    return (m*(mb*b+i) + baby_idx)*n + start + ((r-start) % n)


        raise SearchspaceExhaustedException("This shouldn't happen; check your arguments")




class PointAtInfinity(WeierstrassPoint):
    def __reprdir__(self):
        return ['curve']


    def __hash__(self):
        return object.__hash__(self)


    def __neg__(self) -> 'WeierstrassPoint':
        return self
    

    def order(self):
        return 1



class WeierstrassCurve(Ring):
    """
    Elliptic curve of form y**2 = x**3 + a*x + b
    """

    def __init__(self, a: RingElement, b: RingElement, ring: Ring=None, base_tuple: tuple=None, cardinality: int=None, check_singularity: bool=True, cm_discriminant: int=None, embedding_degree: int=None):
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

        if not ring:
            if not hasattr(a, 'ring'):
                ring = b.ring

            elif not hasattr(b, 'ring'):
                ring = a.ring

            else:
                if a.ring.is_superstructure_of(b.ring):
                    ring = a.ring
                else:
                    ring = b.ring


        self.ring = ring or a.ring
        self.a    = self.ring(a)
        self.b    = self.ring(b)


        if check_singularity:
            if (4 * a**3 + 27 * b**2) == self.ring.zero:
                raise ValueError("Elliptic curve can't be singular")

        if base_tuple:
            base_tuple = WeierstrassPoint(*base_tuple, self)

        self.G_cache     = base_tuple
        self.dpoly_cache = {}

        self.cardinality_cache = cardinality
        self.curve_poly_ring   = self[Symbol('x'), Symbol('y')]

        self.zero = PointAtInfinity(self.ring.zero, self.ring.one, self, self.ring.zero)
        self.PAF_cache = self.zero
        self.__cm_discriminant_cache = cm_discriminant
        self.__embedding_degree = embedding_degree



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


    def coerce(self, x: 'RingElement', y: 'RingElement'=None, verify: bool=True) -> WeierstrassPoint:
        if issubclass(type(x), WeierstrassPoint):
            if x.curve == self:
                return x
            else:
                return self(x.x, x.y)

        if y is not None:
            x, y = self.ring(x), self.ring(y)
            if verify and y**2 != x**3 + self.a*x + self.b:
                raise CoercionException(f'Point ({x}, {y}) not on curve')

            return WeierstrassPoint(x, y, self)
        else:
            return self.recover_point_from_x(x)


    def __call__(self, x: 'RingElement', y: 'RingElement'=None, verify: bool=True) -> WeierstrassPoint:
        return self.coerce(x, y, verify)


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
        return self.ring.characteristic()
    

    def defining_polynomial(self) -> 'Polynomial':
        from samson.math.symbols import Symbol
        x = Symbol('x')
        _ = self.ring[x]
        return x**3 + self.a*x + self.b


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


    def formal_group(self) -> 'EllipticCurveFormalGroup':
        from samson.math.algebra.curves.elliptic_curve_formal_group import EllipticCurveFormalGroup
        return EllipticCurveFormalGroup(self)


    def frobenius_endomorphism(self) -> Map:
        F = self.ring.frobenius_endomorphism()
        return Map(domain=self, codomain=self, map_func=lambda P: self(F(P.x), F(P.y)))


    def find_gen(self) -> WeierstrassPoint:
        return self.abelian_group_generators()[0]
    

    def a_invariants(self):
        z = self.ring.zero
        return z, z, z, self.a, self.b


    def b_invariants(self):
        a1, a2, a3, a4, a6 = self.a_invariants()

        a12 = a1**2
        a32 = a3**2
        a24 = a2*4
        a64 = a6*4
        return a12 + a24, a1*a3 + a4*2, a32 + a64, a12 * a6 + a24 + a64 - a1*a3*a4 + a2*a32 - a4**2


    def c_invariants(self):
        b2, b4, b6, _b8 = self.b_invariants()
        return b2**2 - b4*24, -b2**3 + b2*b4*36 - b6*216
    

    @RUNTIME.global_cache()
    def isomorphisms(self, other: 'WeierstrassCurve') -> list:
        """
        References:
            https://github.com/sagemath/sage/blob/develop/src/sage/schemes/elliptic_curves/ell_generic.py#L2283
        """
        from samson.math.symbols import Symbol
        from samson.math.algebra.curves.elliptic_curve_isomorphism import EllipticCurveIsomorphism

        E, F = self, other
        j    = E.j_invariant()
        R    = E.ring

        if j != other.j_invariant():
            raise NoSolutionException('Curves are not isomorphic')

        a1E, a2E, a3E, _a4E, _a6E = E.a_invariants()
        a1F, a2F, a3F, _a4F, _a6F = F.a_invariants()
        c4E, c6E = E.c_invariants()
        c4F, c6F = F.c_invariants()

        if not j:
            m, um = 6, c6E/c6F

        elif j == R(1728):
            m, um = 4, c4E/c4F

        else:
            m, um = 2, (c6E*c4F)/(c6F*c4E)

        x  = Symbol('x')
        _P = R[x]
        us = list((x**m - um).roots())

        isos = []
        for u in us:
            s = (a1F*u - a1E)/2
            r = (a2F*u**2 + a1E*s + s**2 - a2E)/3
            t = (a3F*u**3 - a1E*r - a3E)/2
            isos.append(EllipticCurveIsomorphism(E, F, u, r, s, t))
        
        return isos



    def cardinality(self, algorithm: EllipticCurveCardAlg=EllipticCurveCardAlg.AUTO, check_supersingular: bool=True) -> int:
        """
        Calculates the cardinality (number of points) of the curve and caches the result.

        Parameters:
            algorithm (EllipticCurveCardAlg): Algorithm to use.
            check_supersingular       (bool): Whether or not to check whether the curve is supersingular.

        Returns:
            int: Cardinality of the curve.

        Examples:
            >>> from samson.math.algebra.curves.weierstrass_curve import EllipticCurve
            >>> from samson.math.algebra.rings.integer_ring import ZZ
            >>> from samson.math.general import find_prime
            >>> # Uses a hybrid of BSGS and Schoofs for medium size curves
            >>> R = ZZ/ZZ(find_prime(20))
            >>> E, _ = EllipticCurve.random_curve(R.quotient)
            >>> E.random()*E.cardinality() == E.zero
            True

            >>> # Includes checks for supersingular curves
            >>> E = EllipticCurve.generate_supersingular_over_ring(R)
            >>> E.is_supersingular()
            True

            >>> E.random()*E.order() == E.zero
            True

            >>> # Uses bruteforce for small curves
            >>> R = ZZ/ZZ(find_prime(10))
            >>> E, _ = EllipticCurve.random_curve(R.quotient)
            >>> E.random()*E.cardinality() == E.zero
            True

        """
        if not self.cardinality_cache:
            p = self.ring.order()

            if check_supersingular and self.is_supersingular():
                _ipp, p, n = is_perfect_power(p)
                if not is_prime(p):
                    raise RuntimeError('Supersingular curve over ring with non-prime power order')

                self.cardinality_cache = (p+1)**n
                return self.cardinality_cache


            if algorithm == EllipticCurveCardAlg.AUTO:
                curve_size = p.bit_length()

                if curve_size < 11:
                    algorithm = EllipticCurveCardAlg.BRUTE_FORCE
                elif curve_size <= 160:
                    algorithm = EllipticCurveCardAlg.BSGS
                else:
                    algorithm = EllipticCurveCardAlg.SCHOOFS


            if algorithm == EllipticCurveCardAlg.BRUTE_FORCE:
                g = self.ring.find_gen()

                # Finite field
                if self.ring.is_field() and self.ring.characteristic() == self.ring.order():
                    p     = self.ring.characteristic()
                    poly  = self.defining_polynomial()
                    total = 1
                    for i in range(g.order()):
                        total += 1+legendre(int(poly(g*i)), p).value

                    order = total

                else:
                    points = []

                    for i in range(g.order()):
                        try:
                            points.append(self(g*i))
                        except NoSolutionException:
                            pass
                    
                    order = len(set(points + [-point for point in points]))+1

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
                n, m = 1, 1
                largest_elem = self.zero

                if p.bit_length() > 64:
                    parity = int(self.defining_polynomial().is_irreducible())

                    # Here we attempt to balance the exponential time BSGS and poly time Schoof
                    trace_mods = [t_mod for t_mod in [3, 5, 7, 11, 13][:round(math.log(p.bit_length(), 3.5))] if t_mod % n or n < 2]

                    # If we're going to 11, we might as well use 3^2, too
                    if 11 in trace_mods:
                        trace_mods[0] = 9

                    if trace_mods:
                        o_con = crt([frobenius_trace_mod_l(self, t_mod) for t_mod in trace_mods])
                        r     = p+1-o_con[0] % o_con[1]
                        order_congruence = (int(r), int(o_con[1]))
                    else:
                        order_congruence = (0, 1)


                    order_congruence = crt([order_congruence, (parity, 2)])
                else:
                    order_congruence = (0, 1)

                # Computes the order of the curve even in non-cyclic groups
                while n*m < (start + p):
                    g = self.random()
                    if g and not g*n:
                        # If this is true, then `n` is the sqrt of the curve's prime.
                        # It's possible this curve is actually sqrt(p)Z x sqrt(p)Z,
                        # so we're looking for a linearly independent point
                        if n == end // 2 - 1:
                            g.order_cache = g.find_maximum_subgroup(n)
                            j, k = g.linear_relation(largest_elem)
                            if not j:
                                m = lcm(m, k)

                        continue


                    g_ord = self.zero.bsgs(g, start=start + p, end=end + p, congruence=crt([(0, n), order_congruence]))
                    n     = lcm(g_ord, n)
                    g.order_cache = g_ord

                    if g_ord != n:
                        g = g.merge(largest_elem)

                    largest_elem = g


                order = n*m
                if not self.G_cache:
                    self.G_cache = largest_elem

                self.cardinality_cache = order

            elif algorithm == EllipticCurveCardAlg.SCHOOFS:
                self.cardinality_cache = schoofs_algorithm(self)

            else:
                raise ValueError(f"Unkown EllipticCurveCardAlg '{algorithm}'")

        return self.cardinality_cache


    def j_invariant(self) -> 'RingElement':
        """
        References:
            https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange#Background
        """
        R  = self.ring
        a3 = R(self.a)**3
        return 1728*((4*a3)/(4*a3 + 27*R(self.b)**2))


    @RUNTIME.global_cache()
    def is_supersingular(self) -> bool:
        """
        References:
            https://en.wikipedia.org/wiki/Supersingular_elliptic_curve#Definition
            "Elliptic Curves: Number Theory and Cryptography, 4.37" (https://people.cs.nctu.edu.tw/~rjchen/ECC2012S/Elliptic%20Curves%20Number%20Theory%20And%20Cryptography%202n.pdf)
        """
        R = self.ring
        p = R.characteristic()
        j = self.j_invariant()

        if p % 3 == 2 and j == R(0):
            return True

        elif p % 4 == 3 and j == R(1728):
            return True

        elif self.cardinality_cache or p < 233:
            return not self.cardinality(check_supersingular=False) % (p+1)

        else:
            _, p, n = is_perfect_power(R.order())
            return is_prime(p) and not self.random()*(p+1)**n



    @RUNTIME.global_cache()
    def embedding_degree(self) -> int:
        if self.__embedding_degree is not None:
            return self.__embedding_degree
        else:
            from samson.math.algebra.rings.integer_ring import ZZ

            Fo = self.ring.order()
            Eo = self.order()

            Zem = (ZZ/ZZ(Eo)).mul_group()
            return Zem(Fo).order()



    def trace_of_frobenius(self) -> int:
        return self.ring.order() + 1 - self.cardinality()


    trace = trace_of_frobenius


    def order(self) -> int:
        return self.cardinality()


    def characteristic(self) -> int:
        return self.G.order()


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


    @RUNTIME.global_cache()
    def cm_discriminant(self) -> int:
        """
        References:
            https://safecurves.cr.yp.to/disc.html
        """
        if self.__cm_discriminant_cache is not None:
            return self.__cm_discriminant_cache
        else:
            from samson.math.algebra.rings.integer_ring import ZZ
            t = self.trace()
            p = self.ring.characteristic()
            D = factor(t**2-4*p, user_stop_func=lambda n, _: ZZ(n).is_square()).square_free().recombine()

            if D % 4 != 1:
                D *= 4

            return D



    @staticmethod
    def from_j(j: RingElement) -> 'WeierstrassCurve':
        """
        Generates a `WeierstrassCurve` with desired `j`-invariant.

        Parameters:
            j (RingElement): `j`-invariant of curve.

        Returns:
            WeierstrassCurve: Constructed curve.
        """
        R = j.ring
        if j == R.zero:
            a, b = R.zero, R.one

        elif j == R(1728):
            a, b = R.one, R.zero

        else:
            k    = j-1728
            a, b = -3*j*k, -2*j*k**2

        return WeierstrassCurve(a, b)


    generate_curve_with_j = from_j


    def quadratic_twist(self, D: RingElement=None) -> 'WeierstrassCurve':
        """
        Returns the quadratic twist by `D`.

        Parameters:
            D (RingElement): Twist parameter:

        Returns:
            WeierstrassCurve: The twist.
        """
        R = self.ring
        p = R.characteristic()

        if D is None:
            while True:
                D = R.random()
                if not D.is_square():
                    break
        else:
            if R(D).is_square():
                raise ValueError(f'Cannot compute quadratic twist. {D} is square')


        b4, b6 = 2*self.a, 4*self.b
        twist  = WeierstrassCurve(8*b4*D**2, 16*b6*D**3)

        if self.cardinality_cache:
            twist.cardinality_cache = 2*p+2-self.order()

        return twist


    def isogeny(self, P: WeierstrassPoint) -> 'EllipticCurveIsogeny':
        """
        Finds the an elliptic curve isogeny whose kernel is `P`.

        Parameters:
            P (WeierstrassPoint): Kernel of isogeny.

        Returns:
            EllipticCurveIsogeny: Isogeny with kernel of `P`.

        References:
            https://epub.jku.at/obvulihs/content/titleinfo/2581853/full.pdf
        """
        EllipticCurveIsogeny = _elliptic_curve_isogeny.EllipticCurveIsogeny

        if P.ring != self:
            raise ValueError(f'{P} is not on {self}')

        E      = self
        n      = P.order()
        n_facs = factor(n)
        phi    = None

        for p, e in n_facs.items():
            Q = P*(n // p**e)

            for i in range(1, e+1):
                phi = EllipticCurveIsogeny(E, Q*(p**(e-i)), pre_isomorphism=phi)
                Q   = phi._rat_map(Q)
                E   = phi.codomain

            P = phi(P)

        return phi


    def _check_trace(self, trace: int) -> bool:
        return not bool(self.random()*(self.p+1-trace))



    @staticmethod
    def generate_curve_with_trace(bit_size: int, trace: int) -> 'WeierstrassCurve':
        """
        Generates a `WeierstrassCurve` with field size `bit_size` and trace `trace`.

        Parameters:
            bit_size (int): Size of the underlying finite field in bits.
            trace    (int): Trace curve should have.

        Returns:
            WeierstrassCurve: Constructed curve.

        Examples:
            >>> from samson.math.algebra.curves.weierstrass_curve import EllipticCurve
            >>> # Can generate curves with odd trace
            >>> EllipticCurve.generate_curve_with_trace(256, 1)._check_trace(1)
            True

            >>> # Can generate curves with negative odd trace
            >>> EllipticCurve.generate_curve_with_trace(256, -13)._check_trace(-13)
            True

            >>> # Can generate curves with even trace
            >>> EllipticCurve.generate_curve_with_trace(256, 2)._check_trace(2)
            True

            >>> # Can generate curves with negative even trace and multiples of 8
            >>> EllipticCurve.generate_curve_with_trace(256, -8)._check_trace(-8)
            True

            >>> # Can generate curves with zero trace
            >>> EllipticCurve.generate_curve_with_trace(256, 0)._check_trace(0)
            True

            >>> # Can generate curves with trace congruent to 5430965739045 % 10861931478090
            >>> EllipticCurve.generate_curve_with_trace(256, 5430965739045)._check_trace(5430965739045)
            True

        """
        hasse_range = hasse_frobenius_trace_interval(2**bit_size)

        if trace not in range(*hasse_range):
            raise ValueError(f"Trace {trace} not within Hasse bounds {hasse_range} for bit_size {bit_size}")

        if trace % 2:
            if trace % 10861931478090 == 5430965739045  or trace % 4555003523070 == 2277501761535:
                return EllipticCurve._generate_curve_with_odd_trace_slow(bit_size, trace)
            else:
                return EllipticCurve._generate_curve_with_odd_trace_fast(bit_size, trace)
        elif not trace:
            return EllipticCurve._generate_supersingular_deg_1(bit_size)
        else:
            return EllipticCurve._generate_curve_with_even_trace(bit_size, trace)



    @staticmethod
    def _generate_supersingular_deg_1(bit_size: int=None, p:int=None) -> 'WeierstrassCurve':
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
    def generate_supersingular_over_ring(R: Ring) -> 'WeierstrassCurve':
        """
        Generates a `WeierstrassCurve` over field `R`.

        Parameters:
            R (Ring): Base field.

        Returns:
            WeierstrassCurve: Constructed curve.

        Examples:
            >>> from samson.math.algebra.curves.weierstrass_curve import EllipticCurve
            >>> from samson.math.algebra.rings.integer_ring import ZZ
            >>> R = ZZ/ZZ(find_prime(20))
            >>> E = EllipticCurve.generate_supersingular_over_ring(R)
            >>> E.is_supersingular()
            True

        """
        from samson.math.algebra.rings.integer_ring import ZZ

        p = R.characteristic()
        Z = ZZ/ZZ(p)

        for i in range(3, 500):
            d = Z(i)

            if (p % 4 == 1) == d.is_square():
                continue

            D = -ZZ(d)

            if D % 4 != 1:
                D *= 4

            try:
                E = EllipticCurve.from_D(int(D), R, strict=False)
                if E.is_supersingular():
                    return E

            except NoSolutionException:
                pass

        raise SearchspaceExhaustedException



    @staticmethod
    def from_D(D: int, R: Ring, strict: bool=True):
        """
        Generates a `WeierstrassCurve` over field `R` with complex multiplication discriminant `D`.

        Parameters:
            D  (int): Complex multiplication discriminant.
            R (Ring): Base field.

        Returns:
            WeierstrassCurve: Constructed curve.
        """
        if strict:
            sols = _get_possible_traces_for_D(D, R.characteristic())

        order  = 0
        Hd     = hilbert_class_polynomial(-D)
        j_invs = Hd.change_ring(R).roots()

        if j_invs:
            E = EllipticCurve.from_j(j_invs[0])

            if E.p.bit_length() > 8 and strict:
                P = E.random()

                def try_trace(t):
                    if not P*(E.p + 1 - t):
                        return E.p + 1 - t

                    elif not P*(E.p + 1 + t):
                        return E.p + 1 + t

                # While we're here, let's get the order
                for t in sols:
                    order = try_trace(t)
                    if order:
                        break

                if order:
                    E.cardinality_cache = order

            return E
        else:
            raise NoSolutionException


    generate_curve_with_D = from_D


    @staticmethod
    def _generate_curve_with_odd_trace_fast(bit_size: int, trace: int) -> 'WeierstrassCurve':
        """
        References:
            "Generating Anomalous Elliptic Curves" (http://www.monnerat.info/publications/anomalous.pdf)
        """
        from samson.math.algebra.rings.integer_ring import ZZ

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


        abs_trace = abs(trace)
        valid_Ds  = [D for D in _D_MAP if gcd(D, abs_trace) == 1]

        # `trace` can't be 5430965739045 mod 10861931478090 or 2277501761535 mod 4555003523070
        # (odd multiples of 3*5*7*17*13 and 3*5*7*17*31, which are the minimum factors to not be coprime to any of our discriminants)
        if not valid_Ds:
            raise ValueError("Odd trace algorithm cannot find suitable discriminant")


        D      = valid_Ds[0]
        m_size = (2**bit_size // D).bit_length() // 2

        # Find a prime such that 4p = x^2 + Dy^2, and x=trace
        # This construction will force the trace to be +-x
        while True:
            m  = random_int_between(2**(m_size-1)+3, 2**m_size)
            m -= (m % 4)-1
            p  = D*m*(m+1) + (D + abs_trace**2) // 4

            if p.bit_length() == bit_size and is_prime(p) and not (4*p - abs_trace**2) % D:
                y2 = (4*p - abs_trace**2) // D
                if ZZ(y2).is_square():
                    break


        # Find a j-invariant
        R = ZZ/ZZ(p)
        E = EllipticCurve.from_D(D, R)
        P = E.random()

        if P*(p+1-trace):
            E = E.quadratic_twist()

        E.cardinality_cache = p+1-trace
        return E


    @staticmethod
    def _generate_curve_with_odd_trace_slow(bit_size: int, trace: int) -> 'WeierstrassCurve':
        from samson.math.algebra.rings.integer_ring import ZZ

        # These discriminants were selected since they are coprime with
        # the ones used in the "fast" algorithm like so:
        # l = lcm(11, 19, 43, 67, 163, 27, 35, 51, 91, 115, 123, 187, 235, 267, 403, 427)
        # possible = [d for d in range(1000) if -d % 4 in [0, 1] and gcd(d, l) == 1 and d % 2 == 1]

        # This shows there's a lot of possible curves even for the smallest value:
        # congruence_bits = (10861931478090).bit_length()
        # approx_primes = pnt(2**congruence_bits)-pnt(2**(congruence_bits-1))
        # num_squares = kth_root(approx_primes // 59, 2)


        for D in [59, 71, 79, 83, 103, 107, 127, 131, 139, 151]:
            start   = 2**(bit_size-1) + 2**(bit_size-2) + 1
            start  -= trace**2
            start //= D
            start  *= 4
            first_root = kth_root(start, 2)

            i = random_int(2**(bit_size // 4) // D)
            p = 0
            while p.bit_length() <= bit_size:
                r  = first_root + i
                p  = (r**2*D + trace**2) // 4
                i += 1

                if p.bit_length() == bit_size and is_prime(p):
                    try:
                        R = ZZ/ZZ(p)
                        E = EllipticCurve.generate_curve_with_D(D, R)
                        if E.trace() == trace:
                            return E
                        elif E.trace() == -trace:
                            return E.quadratic_twist()

                    except NoSolutionException:
                        pass
        
        raise NoSolutionException("No suitable discriminant/prime found")



    @staticmethod
    def _generate_curve_with_even_trace(bit_size: int, trace: int) -> 'WeierstrassCurve':
        """
        References:
            "ELLIPTIC CURVES OF NEARLY PRIME ORDER." (https://eprint.iacr.org/2020/001.pdf)
        """
        from samson.math.algebra.rings.integer_ring import ZZ

        def build_curve(p, a, negate):
            mod = -negate*2 + 1
            R   = ZZ/ZZ(p)
            o   = p + 1 + a*2
            E   = EllipticCurve(R(mod*a), R(0))

            if not E.random()*o:
                E.cardinality_cache = o
                return E

            E = E.quadratic_twist()

            if not E.random()*o:
                E.cardinality_cache = o
                return E



        # Uses primes that are 5 mod 8
        # Cannot tolerate traces divisible by 8
        def five_mod_eight_gen(p, a):
            E = None
            if p % 8 == 5:
                pdash = (p-3) // 2

                if is_prime(pdash):
                    E = build_curve(p, a, False)


                pbar = (p+5) // 2
                if is_prime(pbar):
                    E = build_curve(p, a, True)

            return E


        # Uses primes that are 1 mod 8
        # Only generates traces divisible by 4
        def one_mod_eight_gen(p, a):
            R  = ZZ/ZZ(p)
            while True:
                k = R.random()
                if not k.is_square():
                    break

            E = EllipticCurve(-k, R(0))
            o = p + 1 - 2*a
            if E.random()*o:
                E = E.quadratic_twist()

            E.cardinality_cache = o
            return E



        if trace % 2:
            raise ValueError("Even trace algorithm can only generate curves with even trace")


        if trace % 8:
            curve_gen_func = five_mod_eight_gen
        else:
            curve_gen_func = one_mod_eight_gen


        # The algorithm fails if trace is negative
        # Instead, remove the negative and return the twist at the end
        abs_trace = trace
        if trace < 0:
            abs_trace = -trace


        # p must be [1, 5] mod 8
        # If a is odd, then b should be even
        a      = abs_trace // 2
        b_size = (2**bit_size - a**2).bit_length() // 2
        b      = 2**(b_size-1) + 2**(b_size-2) - random_int(2**(b_size-5))*2 + ((a+1) % 2)
        max_b  = 2**b_size

        E = None
        while b < max_b:
            b += 2
            p  = a**2 + b**2
            if is_prime(p):
                E = curve_gen_func(p, a)

                if E:
                    if E.trace() != trace:
                        E = E.quadratic_twist()
                    return E


        raise SearchspaceExhaustedException



    @staticmethod
    def generate_curve_with_order(order: int, max_r: int=20) -> 'WeierstrassCurve':
        """
        Generates the curve with the prescribed order.

        Parameters:
            order (int): Order of the curve to generate.

        Returns:
            WeierstrassCurve: Generated curve.

        References:
            "Constructing elliptic curves of prime order" (http://www.math.leidenuniv.nl/~psh/bs.pdf)
        """
        from samson.math.algebra.rings.integer_ring import ZZ

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
                                for t in _get_possible_traces_for_D(D, N):
                                    for trace in [t, -t]:
                                        prime = N + 1 - trace

                                        if is_prime(prime):
                                            return D, prime

                            except NoSolutionException:
                                pass

            raise NoSolutionException

        # Find suitable prime and discriminant
        D, p = construct_prime(order, max_r)
        Zp   = ZZ/ZZ(p)
        E    = EllipticCurve.from_D(D, Zp)

        # Either this curve or the twist has the correct order
        if E.random()*order:
            E = E.quadratic_twist()

        E.cardinality_cache = order
        return E



    @staticmethod
    def generate_curve_with_prime_order(size: int, return_both: bool=False) -> 'WeierstrassCurve':
        """
        Generates a curve with a prime order. This method actually finds two prime curves,
        so the `return_both` determines whether to include the second.

        Parameters:
            size         (int): Size in bits of the curve to generate.
            return_both (bool): Whether or not to return both prime curves.

        Returns:
            WeierstrassCurve: Generated curve.
        """
        from samson.math.algebra.rings.integer_ring import ZZ

        d_fields = [ZZ/ZZ(d) for d in _D_MAP]

        while True:
            p = find_prime(size)
            R = ZZ/ZZ(p)

            for DR in d_fields:
                d = DR.characteristic()

                if DR(p).is_square() and R(d).is_square():
                    try:
                        for t,_ in cornacchias_algorithm(d, 4*p, all_sols=True):
                            for trace in [t, -t]:
                                n = p+1-trace

                                if is_prime(n):
                                    E1 = EllipticCurve.generate_curve_with_D(d, R)

                                    if E1.random()*n:
                                        E1 = E1.quadratic_twist()


                                    result = E1

                                    if return_both:
                                        E2 = EllipticCurve.generate_curve_with_D(d, ZZ/ZZ(n))

                                        if E2.random()*p:
                                            E2 = E2.quadratic_twist()
                                        
                                        result = (E1, E2)

                                    return result

                    except NoSolutionException:
                        pass



    @RUNTIME.global_cache()
    def to_montgomery_form(self) -> ('MontgomeryCurve', Map):
        """
        Finds an equivalent Montgomery curve if it exists.

        Returns:
            (MontgomeryCurve, Map): Formatted as (equivalent MontgomeryCurve, map to convert points).

        Examples:
            >>> from samson.math.algebra.curves.weierstrass_curve import EllipticCurve
            >>> # Generate a curve with order divisble by 4
            >>> E = EllipticCurve.generate_curve_with_trace(80, 6)
            >>> M, phi = E.to_montgomery_form()
            >>> P = E.random()
            >>> d = random_int(P.order())
            >>> Q = P*d
            >>> phi(P)*d == phi(Q)
            True

        References:
            https://en.wikipedia.org/wiki/Montgomery_curve#Equivalence_with_Weierstrass_curves
        """
        from samson.math.symbols import Symbol
        from samson.math.algebra.curves.montgomery_curve import MontgomeryCurve

        # Order must be divisible by 4
        if self.order() % 4:
            raise NoSolutionException("Order must be divisible by 4")


        z = Symbol('z')
        _ = self.ring[z]

        # Curve equation must have roots
        roots = self.defining_polynomial().roots()

        if not roots:
            raise NoSolutionException("Curve equation has no roots")


        # Derivative at root must be a square
        for alpha in roots:
            delta = 3*alpha**2 + self.a

            if not delta.is_square():
                continue

            s = ~delta.sqrt()

            if self.G_cache:
                x, y = s*(self.G.x-alpha), self.G.y*s
            else:
                x, y = None, None
            
            A     = 3*alpha*s
            curve = MontgomeryCurve(A=A, B=s, U=x, V=y, order=self.order() // 2)

            inv_B  = ~s
            inv_B3 = ~(s*3)

            def inv_map_func(point):
                return self((point.x*inv_B) + (A*inv_B3), point.y*inv_B)

            point_map = Map(self, curve, lambda point: curve(s*(point.x-alpha), s*point.y), inv_map=inv_map_func)
            return curve, point_map

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


    def random(self, size: 'RingElement'=None) -> WeierstrassPoint:
        """
        Generate a random element.

        Parameters:
            size (RingElement): The ring-specific 'size' of the element.
    
        Returns:
            WeierstrassPoint: Random element of the algebra.
        """
        while True:
            try:
                return self.recover_point_from_x(self.ring.random(size))
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

        if n == -1:
            d_poly = self.curve_poly_ring(4*x**3 + 4*a*x + 4*b)

        elif n in [0, 1]:
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


    def abelian_group_generators(self) -> (WeierstrassPoint, WeierstrassPoint):
        """
        Finds two generators that together fully generate the curve. This is useful when
        the curve is isomorphic to a direct product of two abelian additive groups and not
        just one.

        Returns:
            (WeierstrassPoint, WeierstrassPoint): Formatted as (Generator of group one, generator of group two).

        Examples:
            >>> from samson.math.algebra.curves.weierstrass_curve import EllipticCurve
            >>> from samson.math.algebra.rings.integer_ring import ZZ
            >>> R = ZZ/ZZ(828109)
            >>> a = R(654207)
            >>> b = R(0)
            >>> card = 828104
            >>> E = EllipticCurve(a, b, cardinality=card)
            >>> G1, G2 = E.abelian_group_generators()
            >>> G1.order()*G2.order() == E.order()
            True

            >>> G1.linear_relation(G2)[0] == 0
            True

        References:
            https://github.com/sagemath/sage/blob/ca088c9c9326542accea1f878e791b82cb37a3e1/src/sage/schemes/elliptic_curves/ell_finite_field.py#L843
        """
        while True:
            N  = self.order()
            P1 = self.zero
            P2 = self.zero

            n1 = 1
            n2 = 1

            # Preload P1 by merging in a bunch of points
            # Hopefully, this brings us close enough to a generator
            for _ in range(10):
                Q = 0
                while not Q:
                    Q = self.random()

                if Q*n1:
                    P1 = P1.merge(Q)
                    n1 = P1.order()


            while True:
                if n1*n2 == N:
                    return P1, P2

                Q = 0
                while not Q:
                    Q = self.random()


                # If Q1 != 0, then it has a factor P1 doesn't, so we should merge it into P1.
                # Additionally, if P2 != 0, we need to update P2 to keep a basis
                if Q*n1:
                    if n2 > 1:
                        P3 = P1 * (n1 // n2)

                    P1 = P1.merge(Q)
                    n1 = P1.order()

                    if n2 > 1:
                        a, m = P1.linear_relation(P3)
                        P3  -= P1 * (a // m)

                        if m == n2:
                            P2 = P3

                        else:
                            a, m = P1.linear_relation(P2)
                            P2 -= P1 * (a // m)

                            P2 = P2.merge(P3)
                            n2 = P2.order()


                # Q's order divides P1's order
                else:
                    n1a = n1 // gcd(n1, N // n1)
                    n1b = n1 // n1a

                    Q_orig = Q
                    Q  *= n1a
                    P1a = P1*n1a

                    # In case Q.order() | P.order(), but are linearly independent (e.g. Z/8 + Z/2)
                    if not Q:
                        a, b = P1.linear_relation(Q_orig)
                        if (not a or n1 % a != 0) and n1*b <= N:
                            P2 = P2.merge(Q_orig*(n1a // b))
                            n2 = P2.order()
                        continue

                    for m in sorted(factor(n1b).divisors()):
                        try:
                            a = bsgs(P1a*m, Q*m, end=(n1b // m))
                            break
                        except SearchspaceExhaustedException:
                            pass

                    a *= m*n1a

                    # If `m` > 1, then P1 and Q are linearly independent,
                    # so let's bring that into our basis
                    if m > 1:
                        Q -= P1 * (a // m)

                        if n2 == 1:
                            P2 = Q
                            n2 = P2.order()
                        else:
                            P2 = P2.merge(Q)
                            n2 = P2.order()



    @RUNTIME.global_cache()
    def additive_transfer_map(self) -> 'Map':
        """
        Generates a map to `Qp` such that if `Q` = `P`*`d`, then `phi(Q)` = `phi(P)`*`d`.

        Returns:
            Map: Map function.

        Examples:
            >>> from samson.math.algebra.curves.weierstrass_curve import EllipticCurve
            >>> E = EllipticCurve.generate_curve_with_trace(256, 1)
            >>> g = E.G
            >>> d = random_int(g.order())
            >>> q = g*d
            >>> phi = E.additive_transfer_map()
            >>> int((phi(q)/phi(g))[0]) == d
            True

        References:
            https://www.hpl.hp.com/techreports/97/HPL-97-128.pdf
            https://hxp.io/blog/25/SharifCTF-2016-crypto350-British-Elevator-writeup/
        """
        from samson.math.algebra.rings.padic_numbers import Qp
        E = self
        p = E.ring.characteristic()

        if self.random() * p:
            raise ValueError(f"{E} is not trace one")


        # Move everything into p-adic numbers
        Qp2  = Qp(p, 8)
        QpA  = Qp2(E.a)
        QpB  = Qp2(E.b)
        Ep   = EllipticCurve(QpA, QpB)
        formal_log = Ep.formal_group().log()

        # Lift points to the new curve
        def lift_point(x, y):
            Qpy = (x ** 3 + QpA * x + QpB).sqrt()
            QpP = Ep(x, (-Qpy, Qpy)[Qpy.val[0] == y])
            return QpP
        

        def add_trans(P):
            QpxP = Qp2(P.x)
            PQp  = lift_point(QpxP, P.y)
            pPQp = p * PQp
            tP   = -pPQp.x / pPQp.y
            return formal_log(tP) / p

        return Map(E, Qp2, add_trans)



EllipticCurve = WeierstrassCurve
