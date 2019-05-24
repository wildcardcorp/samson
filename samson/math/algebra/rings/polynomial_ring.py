from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.polynomial import Polynomial

class PolynomialElement(RingElement):
    def __init__(self, val: Polynomial, ring: Ring):
        self.val  = val
        self.ring = ring
    
    def __repr__(self):
        return f"<PolynomialElement val={self.val}, ring={self.ring}>"

    def __str__(self):
        return self.__repr__()
    

    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}({self.val.shorthand()})'


    def __add__(self, other: object) -> object:
        return PolynomialElement(self.val + other.val, self.ring)

    def __sub__(self, other: object) -> object:
        return PolynomialElement(self.val - other.val, self.ring)

    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return super().__mul__(other)

        return PolynomialElement(self.val * other.val, self.ring)

    def __truediv__(self, other: object) -> object:
        return PolynomialElement(self.val / other.val, self.ring)

    def __mod__(self, other: object) -> object:
        return PolynomialElement(self.val % other.val, self.ring)

    def __neg__(self) -> object:
        return PolynomialElement(-self.val, self.ring)


class PolynomialRing(Ring):
    ELEMENT = PolynomialElement

    def __init__(self, field):
        self.field = field


    @property
    def characteristic(self):
        return self.field.characteristic


    def zero(self) -> Polynomial:
        return PolynomialElement(Polynomial([self.field(0)], self.field), self)

    def one(self) -> Polynomial:
        return PolynomialElement(Polynomial([self.field(1)], self.field), self)
    

    def __repr__(self):
        return f"<PolynomialRing field={self.field}>"

    def __str__(self):
        return self.__repr__()
    

    def shorthand(self) -> str:
        return f'{self.field.shorthand()}[x]'

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.field == other.field
