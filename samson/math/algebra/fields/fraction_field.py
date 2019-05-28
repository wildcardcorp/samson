from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.ring import Ring
from samson.math.general import gcd


class FractionFieldElement(FieldElement):

    def __init__(self, numerator: FieldElement, denominator: FieldElement, field: Field, simplify: bool=True):
        if simplify:
            divisor       = gcd(numerator, denominator)
            numerator   //= divisor
            denominator //= divisor

        if denominator == field.ring.zero():
            raise ZeroDivisionError

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
        return int(self.numerator) / int(self.denominator)



class FractionField(Field):
    ELEMENT = FractionFieldElement

    def __init__(self, ring: Ring):
        self.ring = ring
    

    def __repr__(self):
        return f"<FractionField: ring={self.ring}>"


    def zero(self) -> FractionFieldElement:
        return FractionFieldElement(self.ring.zero(), self.ring.one(), self)


    def one(self) -> FractionFieldElement:
        return FractionFieldElement(self.ring.one(), self.ring.one(), self)


    def shorthand(self) -> str:
        return f'Frac({self.ring})'


    def coerce(self, other: object) -> object:
        if type(other) is FractionFieldElement:
            return other

        elif type(other) is tuple:
            if len(other) < 2:
                denom = self.ring.one()
            else:
                denom = self.ring.coerce(other[1])
            
            result = (self.ring.coerce(other[0]), denom)
        else:
            result = (self.ring.coerce(other), self.ring.one())

   
        return FractionFieldElement(*result, self)
