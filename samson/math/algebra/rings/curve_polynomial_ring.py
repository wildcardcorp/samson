from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.polynomial import Polynomial
from sympy import Expr
from sympy.abc import x

class CurvePolynomialElement(RingElement):
    def __init__(self, x_poly: Polynomial, y_poly: Polynomial, ring: Ring):
        self.x_poly = x_poly
        self.y_poly = y_poly or ring.poly_ring.zero().val
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

        # print('self.x', self.x_poly)
        # print('self.y', self.y_poly)
        # print('other.x', other.x_poly)
        # print('other.y', other.y_poly)
        # print('self', self)
        # print('other', other)
        # print('x', nx)
        # print('xy', xy)
        # print('yx', yx)
        # print('y', y)

        if self.y_poly and other.y_poly:
            #print('y2_red', self.ring.poly_ring(x**3 + self.ring.a*x + self.ring.b).val)
            #nx += (self.y_poly * other.y_poly) / self.ring.poly_ring(x**2).val * self.ring.poly_ring(x**3 + self.ring.a*x + self.ring.b).val
            nx += self.y_poly * other.y_poly * self.ring.poly_ring(x**3 + self.ring.a*x + self.ring.b).val

        # print('FINAL X', nx)
        # print()
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
    ELEMENT = CurvePolynomialElement

    def __init__(self, poly_ring, a, b):
        self.poly_ring = poly_ring
        self.a = a
        self.b = b


    @property
    def characteristic(self):
        return self.poly_ring.field.characteristic


    def zero(self) -> CurvePolynomialElement:
        return CurvePolynomialElement(Polynomial([self.poly_ring.field(0)], self.poly_ring.field), None, self)

    def one(self) -> CurvePolynomialElement:
        return CurvePolynomialElement(Polynomial([self.poly_ring.field(1)], self.poly_ring.field), None, self)


    def __repr__(self):
        return f"<CurvePolynomialRing poly_ring={self.poly_ring}>"


    def shorthand(self) -> str:
        return f'{self.poly_ring.shorthand()}[y]'

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.poly_ring == other.poly_ring and self.a == other.a and self.b == other.b


    def coerce(self, other: object) -> CurvePolynomialElement:
        if type(other) is CurvePolynomialElement:
            return other
        
        if type(other) is tuple:
            x_poly = other[0]
            y_poly = other[1] or self.poly_ring.zero().val
        else:
            x_poly = other
            y_poly = self.poly_ring.zero().val

        coerced = []
        for poly in [x_poly, y_poly]:
            if type(poly) is list or issubclass(type(poly), Expr):
                coerced.append(Polynomial(poly, self.poly_ring.field))

            elif type(poly) is Polynomial:
                coerced.append(poly)
            
            elif type(poly) is int:
                coerced.append(Polynomial([poly], self.poly_ring.field))

            else:
                raise Exception('Coercion failed')
        
        return CurvePolynomialElement(*coerced, ring=self)
