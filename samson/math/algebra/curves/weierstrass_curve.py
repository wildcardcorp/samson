from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.math.polynomial import Polynomial
from samson.math.algebra.curves.util import EllipticCurveCardAlg
from samson.math.general import random_int, tonelli


class WeierstrassPoint(RingElement):
    """
    Point on a Weierstrass curve.
    """

    def __init__(self, x: int, y: int, curve: object):
        self.x     = curve.ring.coerce(x)
        self.y     = curve.ring.coerce(y)
        self.curve = curve
        self.order_cache = None


    def __repr__(self):
        return f"<WeierstrassPoint: x={self.x}, y={self.y}, curve={self.curve}>"


    def shorthand(self) -> str:
        return f'{self.curve.shorthand()}({{x={self.x}, y={self.y}}})'


    @property
    def ring(self):
        return self.curve


    @property
    def val(self):
        return self.x


    @property
    def order(self) -> int:
        from samson.math.general import bsgs, hasse_frobenius_trace_interval
        if not self.order_cache:
            start, end = hasse_frobenius_trace_interval(self.curve.p)
            order      = bsgs(self, self.curve.POINT_AT_INFINITY, e=self.curve.POINT_AT_INFINITY, start=start + self.curve.p, end=end + self.curve.p)
            self.order_cache = order

        return self.order_cache


    def __hash__(self):
        return hash(self.curve) ^ hash(self.x) ^ hash(self.y)


    def __int__(self) -> int:
        return int(self.x)


    def __eq__(self, P2: object) -> bool:
        return self.curve == P2.curve and self.x == P2.x and self.y == P2.y


    def __lt__(self, other: object) -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.x < other.x


    def __gt__(self, other: object) -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.x > other.x


    def __neg__(self) -> object:
        return WeierstrassPoint(self.x, -self.y, self.curve)


    @left_expression_intercept
    def __add__(self, P2: object) -> object:
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


    def __radd__(self, P2: object) -> object:
        return self.__add__(P2)

    @left_expression_intercept
    def __sub__(self, P2: object) -> object:
        return self + (-P2)

    def __rsub__(self, P2: object) -> object:
        return -self + P2

    @left_expression_intercept
    def __truediv__(self, other: object) -> object:
        from samson.math.general import pohlig_hellman

        g = self.ring.coerce(other)
        return pohlig_hellman(g, self, self.ring.order)


    __floordiv__ = __truediv__



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

        self.a  = a
        self.b  = b
        self.ring = ring or self.a.ring

        if check_singularity:
            if (4 * a**3 - 27 * b**2) == self.ring.zero():
                raise ValueError("Elliptic curve can't be singular")

        if base_tuple:
            base_tuple = WeierstrassPoint(*base_tuple, self)

        self.G_cache     = base_tuple
        self.PAF_cache   = None
        self.dpoly_cache = {}

        self.cardinality_cache = cardinality
        self.curve_poly_ring   = self[Symbol('x'), Symbol('y')]



    def __repr__(self):
        return f"<WeierstrassCurve: a={self.a}, b={self.b}, cardinality={self.cardinality_cache}, ring={self.ring}, G={(str(self.G_cache.x), str(self.G_cache.y)) if self.G_cache else self.G_cache}>"


    def zero(self) -> WeierstrassPoint:
        """
        Returns:
            WeierstrassPoint: '0' element of the algebra.
        """
        return WeierstrassPoint(0, 0, self)


    def one(self) -> WeierstrassPoint:
        """
        Returns:
            WeierstrassPoint: '1' element of the algebra.
        """
        return self.G


    def shorthand(self) -> str:
        return f'WeierstrassCurve{{a={self.a}, b={self.b}}}'


    def __getitem__(self, args):
        from samson.math.algebra.rings.curve_polynomial_ring import CurvePolynomialRing
        if type(args) is tuple:
            return CurvePolynomialRing(self.ring[args[0]], self.a, self.b)
        else:
            return super().__getitem__(args)


    def __call__(self, x: object, y: object=None) -> WeierstrassPoint:
        if y:
            return WeierstrassPoint(x, y, self)
        else:
            return self.recover_point_from_x(x)


    def __eq__(self, other: object) -> bool:
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


    def cardinality(self, algorithm: EllipticCurveCardAlg=EllipticCurveCardAlg.AUTO) -> int:
        """
        Calculates the cardinality (number of points) of the curve and caches the result.

        Parameters:
            algorithm (EllipticCurveCardAlg): Algorithm to use.
        
        Returns:
            int: Cardinality of the curve.
        """
        from samson.math.general import schoofs_algorithm

        if not self.cardinality_cache:
            if algorithm == EllipticCurveCardAlg.AUTO:
                curve_size = self.p.bit_length()
                if curve_size <= 96:
                    self.cardinality_cache = self.G.order
                else:
                    self.cardinality_cache = schoofs_algorithm(self)

            elif algorithm == EllipticCurveCardAlg.BSGS:
                self.cardinality_cache = self.G.order

            elif algorithm == EllipticCurveCardAlg.SCHOOFS:
                self.cardinality_cache = schoofs_algorithm(self)

            else:
                raise Exception(f"Unkown EllipticCurveCardAlg '{algorithm}'")

        return self.cardinality_cache


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
            self.G_cache = self.random()

        return self.G_cache


    @property
    def POINT_AT_INFINITY(self) -> WeierstrassPoint:
        if not self.PAF_cache:
            self.PAF_cache = self.zero()

        return self.PAF_cache


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
        y = tonelli(pow(x, 3, self.p) + int(self.a*x) + int(self.b), self.p)
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
                return self.recover_point_from_x(max(1, random_int(int(size.x) if size else self.p)))
            except AssertionError:
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
