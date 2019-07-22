from samson.math.algebra.rings.ring import Ring, RingElement
from samson.utilities.exceptions import CoercionException
from samson.math.algebra.rings.polynomial_ring import PolynomialRing
from samson.math.polynomial import Polynomial
from sympy import Expr
from sympy.abc import x

class CurvePolynomialElement(RingElement):
    """
    Element of a `CurvePolynomialRing`.
    """

    def __init__(self, x_poly: Polynomial, y_poly: Polynomial, ring: Ring):
        """
        Parameters:
            x_poly (Polynomial): Polynomial representing the x-coordinate.
            y_poly (Polynomial): Polynomial representing the y-coordinate.
            ring         (Ring): Parent ring.
        """
        self.x_poly = x_poly
        self.y_poly = y_poly or ring.poly_ring.zero()
        self.ring   = ring

    def __repr__(self):
        return f"<CurvePolynomialElement x_poly={self.x_poly}, y_poly={self.y_poly}, ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}({self.x_poly.shorthand()}, {self.y_poly.shorthand()})'


    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return CurvePolynomialElement(self.x_poly + other.x_poly, self.y_poly + other.y_poly, self.ring)

    def __sub__(self, other: object) -> object:
        return CurvePolynomialElement(self.x_poly - other.x_poly, self.y_poly - other.y_poly, self.ring)

    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return super().__mul__(other)

        other = self.ring.coerce(other)

        nx = self.x_poly * other.x_poly
        xy = self.x_poly * other.y_poly
        yx = self.y_poly * other.x_poly

        y = xy + yx

        if self.y_poly and other.y_poly:
            nx += self.y_poly * other.y_poly * self.ring.poly_ring(x**3 + self.ring.a*x + self.ring.b)

        return CurvePolynomialElement(nx, y, self.ring)


    def __divmod__(self, other: object) -> object:
        if not other:
            raise ZeroDivisionError

        if not self:
            return self.ring.zero(), self.ring.zero()

        if other.y_poly and (self.x_poly or other.x_poly):
            raise Exception("Multivariate polynomial division not supported")


        if other.x_poly:
            qx, rx = divmod(self.x_poly, other.x_poly)
            qy, ry = divmod(self.y_poly, other.x_poly)
        else:
            qx, rx = divmod(self.y_poly, other.y_poly)
            qy, ry = self.ring.zero().x_poly, self.ring.zero().x_poly

        return (CurvePolynomialElement(qx, qy, self.ring), CurvePolynomialElement(rx, ry, self.ring))


    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self.__divmod__(other)[0]

    __floordiv__ = __truediv__

    def __mod__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self.__divmod__(other)[1]

    def __neg__(self) -> object:
        return CurvePolynomialElement(-self.x_poly, -self.y_poly, self.ring)


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.x_poly == other.x_poly and self.y_poly == other.y_poly and self.ring == other.ring


    def __bool__(self) -> bool:
        return bool(self.x_poly) or bool(self.y_poly)


class CurvePolynomialRing(Ring):
    """
    Polynomial ring that represents an Elliptic curve.
    """

    def __init__(self, poly_ring: PolynomialRing, a: int, b: int):
        """
        Parameters:
            poly_ring (PolynomialRing): Underlying polynomial ring.
            a                    (int): `a` coefficient of the curve.
            b                    (int): `b` constant of the curve.
        """
        self.poly_ring = poly_ring
        self.a = a
        self.b = b


    @property
    def characteristic(self):
        return self.poly_ring.ring.characteristic


    def zero(self) -> CurvePolynomialElement:
        """
        Returns:
            CurvePolynomialElement: '0' element of the algebra.
        """
        return CurvePolynomialElement(Polynomial([self.poly_ring.ring(0)], self.poly_ring.ring), None, self)


    def one(self) -> CurvePolynomialElement:
        """
        Returns:
            CurvePolynomialElement: '1' element of the algebra.
        """
        return CurvePolynomialElement(Polynomial([self.poly_ring.ring(1)], self.poly_ring.ring), None, self)


    def random(self, size: int=None) -> CurvePolynomialElement:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            CurvePolynomialElement: Random element of the algebra.
        """
        return CurvePolynomialElement(self.poly_ring.random(size.x_poly), None, self)


    def __repr__(self):
        return f"<CurvePolynomialRing poly_ring={self.poly_ring}>"


    def shorthand(self) -> str:
        return f'{self.poly_ring.shorthand()}[y]'

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.poly_ring == other.poly_ring and self.a == other.a and self.b == other.b


    def __hash__(self) -> int:
        return hash((self.poly_ring, self.__class__, self.a, self.b))


    def coerce(self, other: object) -> CurvePolynomialElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            CurvePolynomialElement: Coerced element.
        """
        if type(other) is CurvePolynomialElement:
            return other

        if type(other) is tuple:
            x_poly = other[0]
            y_poly = other[1] or self.poly_ring.zero()
        else:
            x_poly = other
            y_poly = self.poly_ring.zero()

        coerced = []
        for poly in [x_poly, y_poly]:
            if type(poly) is list or issubclass(type(poly), Expr):
                coerced.append(Polynomial(poly, self.poly_ring.ring))

            elif type(poly) is Polynomial:
                coerced.append(poly)

            elif type(poly) is int:
                coerced.append(Polynomial([poly], self.poly_ring.ring))

            else:
                raise CoercionException('Coercion failed')

        return CurvePolynomialElement(*coerced, ring=self)
