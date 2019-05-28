from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.ring import Ring
from samson.math.general import gcd


class FractionFieldElement(FieldElement):

    def __init__(self, numerator: FieldElement, denominator: FieldElement, field: Field, simplify: bool=True):
        if simplify:
            divisor       = gcd(numerator, denominator)
            numerator   //= divisor
            denominator //= divisor

        self.numerator   = numerator
        self.denominator = denominator
        self.field       = field


    def __repr__(self):
        return f"<FractionFieldElement: numerator={self.numerator}, denominator={self.denominator}, ring={self.ring}>"
    

    def shorthand(self) -> str:
        return f'{self.field.shorthand()}({self.numerator}/{self.denominator})'


    def __eq__(self, other: object):
        return type(self) == type(other) and self.numerator * other.denominator == self.denominator * other.numerator

    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return FractionFieldElement(self.numerator * other.denominator + self.denominator * other.numerator, self.denominator * other.denominator, self.ring)

    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self + (-other)

    def __mul__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return FractionFieldElement(self.numerator * other.numerator, self.denominator * other.denominator, self.ring)

    def __truediv__(self, other: object) -> object:
        return self * (~self.ring.coerce(other))
    
    __floordiv__ = __truediv__

    def __neg__(self) -> object:
        return FractionFieldElement(-self.numerator, self.denominator, self.ring)
    
    def __invert__(self) -> object:
        if not self:
            raise ZeroDivisionError

        return FractionFieldElement(self.denominator, self.numerator, self.ring)


    def __float__(self):
        return self.numerator / self.denominator



class FractionField(Field):
    ELEMENT = FractionFieldElement

    def __init__(self, ring: Ring):
        self.ring = ring
    

    def __repr__(self):
        return f"<FractionField: ring={self.ring}>"


    def zero(self) -> FractionFieldElement:
        return FractionFieldElement(0, 1, self)


    def one(self) -> FractionFieldElement:
        return FractionFieldElement(1, 1, self)


    def shorthand(self) -> str:
        return f'Frac({self.ring})'


    def coerce(self, other: int) -> object:
        if type(other) == FractionFieldElement:
            return other

        elif type(other) is int:
            result = (other, 1)

        elif type(other) is tuple:
            result = other

            if len(result) < 2:
                result = (result[0], 1)
            
   
        return FractionFieldElement(*result, self)
