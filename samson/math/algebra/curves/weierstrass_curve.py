from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.polynomial import Polynomial
from samson.math.general import random_int, tonelli
from sympy import Poly
from sympy.abc import x, y


class WeierstrassPoint(RingElement):
    def __init__(self, x, y, curve):
        self.x     = curve.ring.coerce(x)
        self.y     = curve.ring.coerce(y)
        self.curve = curve


    def __repr__(self):
        return f"<WeierstrassPoint: x={self.x}, y={self.y}, curve={self.curve}>"


    @property
    def ring(self):
        return self.curve


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
    def __init__(self, a: RingElement, b: RingElement, ring: Ring=None, base_tuple: tuple=None, order: int=None):
        self.a  = a
        self.b  = b
        self.ring = ring or self.a.ring

        if base_tuple:
            base_tuple = WeierstrassPoint(*base_tuple, self)

        self.G_cache     = base_tuple
        self.POF_cache   = None
        self.dpoly_cache = {}
        self.order_cache = order

        self.curve_poly_ring = self[x, y]



    def __repr__(self):
        return f"<WeierstrassCurve: a={self.a}, b={self.b}, order={self.order_cache}, ring={self.ring}, G={(str(self.G_cache.x), str(self.G_cache.y)) if self.G_cache else self.G_cache}>"


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


    @property
    def p(self):
        return int(self.ring.quotient.val)


    @property
    def order(self) -> int:
        from samson.math.general import bsgs, hasse_frobenius_trace_interval
        if not self.order_cache:
            start, end = hasse_frobenius_trace_interval(self.p)
            order      = bsgs(self.G, self.POINT_AT_INFINITY, e=self.POINT_AT_INFINITY, start=start, end=end)
            self.order_cache = order

        return self.order_cache


    @property
    def G(self) -> WeierstrassPoint:
        if not self.G_cache:
            self.G_cache = self.random_point()

        return self.G_cache


    @property
    def POINT_AT_INFINITY(self) -> WeierstrassPoint:
        if not self.POF_cache:
            self.POF_cache = self.zero()

        return self.POF_cache


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
            #d_poly = Poly(n, gens=x)
            d_poly = self.curve_poly_ring(n)
        elif n == 2:
            #d_poly = Poly(2*y)
            d_poly = self.curve_poly_ring(2*y)
        elif n == 3:
            # d_poly = Poly(3*x**4 + 6 * a*x**2 + 12 * b*x - a**2, gens=[x, y])
            # d_poly = Poly(3*x**4 + 6 * a*x**2 + 12 * b*x - a**2, gens=[x])
            d_poly = self.curve_poly_ring(3*x**4 + 6*a*x**2 + 12*b*x - a**2)
        elif n == 4:
            # d_poly = Poly(4*y * (x**6 + 5*a * x**4 + 20*b*x**3 - 5*a**2 * x**2 - 4*a*b*x - 8*b**2 - a**3))
            d_poly = self.curve_poly_ring((-4*a**3 - 32*b**2)*x**6 - 16*a*b*x**5 - 20*a**2*x**4 + 80*b*x**3 + 20*a*x**2 + 4)
        elif n % 2 == 1:
            m = n // 2
            d_poly = self.division_poly(m + 2) * self.division_poly(m)**3 - self.division_poly(m - 1) * self.division_poly(m + 1)**3
        elif n % 2 == 0:
            m = n // 2#y
            d_poly = (self.division_poly(m) // 2 * self.curve_poly_ring(x)) * (self.division_poly(m + 2) * self.division_poly(m - 1)**2 - self.division_poly(m - 2) * self.division_poly(m + 1)**2)


        self.dpoly_cache[n] = d_poly

        return d_poly
