from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.polynomial import Polynomial
from samson.math.algebra.curves.util import EllipticCurveCardAlg
from samson.math.general import random_int, tonelli
from sympy import Poly
from sympy.abc import x, y


class WeierstrassPoint(RingElement):
    def __init__(self, x, y, curve):
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
    def order(self) -> int:
        from samson.math.general import bsgs, hasse_frobenius_trace_interval
        if not self.order_cache:
            start, end = hasse_frobenius_trace_interval(self.curve.p)
            order      = bsgs(self, self.curve.POINT_AT_INFINITY, e=self.curve.POINT_AT_INFINITY, start=start + self.curve.p, end=end + self.curve.p)
            self.order_cache = order

        return self.order_cache


    def __hash__(self):
        return int(self.x.val) * int(self.y.val) + self.curve.p


    def __eq__(self, P2: object) -> bool:
        return self.curve == P2.curve and self.x == P2.x and self.y == P2.y


    def __neg__(self) -> object:
        return WeierstrassPoint(self.x, -self.y, self.curve)


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

    def __sub__(self, P2: object) -> object:
        return self + (-P2)

    def __rsub__(self, P2: object) -> object:
        return -self + P2




class WeierstrassCurve(Ring):
    def __init__(self, a: RingElement, b: RingElement, ring: Ring=None, base_tuple: tuple=None, cardinality: int=None):
        self.a  = a
        self.b  = b
        self.ring = ring or self.a.ring

        if base_tuple:
            base_tuple = WeierstrassPoint(*base_tuple, self)

        self.G_cache     = base_tuple
        self.PAF_cache   = None
        self.dpoly_cache = {}

        self.cardinality_cache = cardinality
        self.curve_poly_ring   = self[x, y]



    def __repr__(self):
        return f"<WeierstrassCurve: a={self.a}, b={self.b}, cardinality={self.cardinality_cache}, ring={self.ring}, G={(str(self.G_cache.x), str(self.G_cache.y)) if self.G_cache else self.G_cache}>"


    def zero(self) -> WeierstrassPoint:
        return WeierstrassPoint(0, 0, self)

    def one(self) -> WeierstrassPoint:
        return self.G


    def shorthand(self) -> str:
        return f'WeierstrassCurve{{a={self.a}, b={self.b}}}'
    

    def __getitem__(self, args):
        from samson.math.algebra.rings.curve_polynomial_ring import CurvePolynomialRing
        if type(args) is tuple:
            return CurvePolynomialRing(self.ring[x], self.a, self.b)
        else:
            return super().__getitem__(args)
    

    def __call__(self, x: object, y: object=None) -> WeierstrassPoint:
        if y:
            return WeierstrassPoint(x, y, self)
        else:
            return self.recover_point_from_x(x)


    @property
    def p(self):
        return int(self.ring.quotient.val)


    def cardinality(self, algorithm: EllipticCurveCardAlg=EllipticCurveCardAlg.AUTO) -> int:
        from samson.math.general import schoofs_algorithm

        if not self.cardinality_cache:
            if algorithm == EllipticCurveCardAlg.AUTO:
                curve_size = self.p.bit_length()
                if curve_size <= 75:
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
    def G(self) -> WeierstrassPoint:
        if not self.G_cache:
            self.G_cache = self.random_point()

        return self.G_cache


    @property
    def POINT_AT_INFINITY(self) -> WeierstrassPoint:
        if not self.PAF_cache:
            self.PAF_cache = self.zero()

        return self.PAF_cache


    def recover_point_from_x(self, x: int) -> object:
        y = tonelli(pow(x, 3, self.p) + int(self.a*x) + int(self.b), self.p)
        return WeierstrassPoint(x, y, self)


    def random_point(self) -> object:
        while True:
            try:
                return self.recover_point_from_x(max(1, random_int(self.p)))
            except AssertionError:
                pass


    def division_poly(self, n: int) -> Poly:
        if n in self.dpoly_cache:
            return self.dpoly_cache[n]

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
            two = self.curve_poly_ring.poly_ring([2]).val
            psi = self.division_poly
            for j in range(5, n+1):
                k, m = divmod(j, 2)

                if m:
                    self.dpoly_cache[j] = psi(k+2) * psi(k)**3 - psi(k+1)**3 * psi(k-1)
                else:
                    if k % 2 == 0:
                        self.dpoly_cache[j] = (psi(k).y_poly // two) * (psi(k+2) * psi(k-1)**2 - psi(k-2) * psi(k+1)**2)
                    else:
                        self.dpoly_cache[j] = y * (psi(k).x_poly // two) * (psi(k+2) * psi(k-1).y_poly**2 - psi(k-2) * psi(k+1).y_poly**2)

            d_poly = self.dpoly_cache[n]


        # elif n % 2 == 1:
        #     m = n // 2
        #     print(f'HERE {n}')
        #     print(m + 2)
        #     print(m)
        #     print(m + 1)
        #     print(m -1)
        #     # d_poly = self.division_poly(m + 2) * self.division_poly(m)**3 - self.division_poly(m - 1) * self.division_poly(m + 1)**3
        #     d_poly = self.division_poly(m + 2) * self.division_poly(m)**3 - self.division_poly(m + 1)**3 * self.division_poly(m - 1)

        # elif n % 2 == 0:
        #     m = n // 2#y
        #     d_poly = (self.division_poly(m) // 2 * self.curve_poly_ring(x)) * (self.division_poly(m + 2) * self.division_poly(m - 1)**2 - self.division_poly(m - 2) * self.division_poly(m + 1)**2)


        self.dpoly_cache[n] = d_poly

        return d_poly
