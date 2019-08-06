from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.ring import Ring, left_expression_intercept
from samson.math.general import gcd


class FractionFieldElement(FieldElement):
    """
    Element of a `FractionField`.
    """

    def __init__(self, numerator: FieldElement, denominator: FieldElement, field: Field):
        """
        Parameters:
            numerator   (FieldElement): Numerator of the fraction.
            denominator (FieldElement): Denominator of the fraction.
            field      (FractionField): Parent field.
        """
        if field.simplify:
            try:
                divisor       = gcd(numerator, denominator)
                numerator   //= divisor
                denominator //= divisor
            except Exception:
                pass

        if denominator == field.ring.zero():
            raise ZeroDivisionError

        self.numerator   = numerator
        self.denominator = denominator
        self.field       = field


    def __repr__(self):
        return f"<FractionFieldElement: numerator={self.numerator}, denominator={self.denominator}, ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.field.shorthand()}({self.numerator}/{self.denominator})'


    def __hash__(self):
        return hash((self.numerator, self.denominator, self.field))

    def __eq__(self, other: object):
        return type(self) == type(other) and self.numerator * other.denominator == self.denominator * other.numerator


    @left_expression_intercept
    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return FractionFieldElement(self.numerator * other.denominator + self.denominator * other.numerator, self.denominator * other.denominator, self.ring)


    @left_expression_intercept
    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self + (-other)


    def __mul__(self, other: object) -> object:
        gmul = self.ground_mul(other)
        if gmul:
            return gmul

        other = self.ring.coerce(other)
        return FractionFieldElement(self.numerator * other.numerator, self.denominator * other.denominator, self.ring)

    @left_expression_intercept
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


    def __lt__(self, other: object) -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.numerator * other.denominator < other.numerator * self.denominator


    def __gt__(self, other: object) -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.numerator * other.denominator > other.numerator * self.denominator


class FractionField(Field):
    """
    Fraction field over a ring.

    Examples:
        >>> from samson.math.algebra.rings.integer_ring import IntegerRing
        >>> QQ = FractionField(IntegerRing())
        >>> assert QQ(5) * QQ((1, 5)) == QQ.one()

    """

    def __init__(self, ring: Ring, simplify: bool=True):
        """
        Parameters:
            ring     (Ring): Underlying ring.
            simplify (bool): Whether or not to simplify the fraction.
        """
        self.ring     = ring
        self.simplify = simplify


    def __repr__(self):
        return f"<FractionField: ring={self.ring}>"


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    @property
    def characteristic(self):
        return self.ring.characteristic


    @property
    def order(self) -> int:
        return self.ring.order**2


    def zero(self) -> FractionFieldElement:
        """
        Returns:
            FractionFieldElement: '0' element of the algebra.
        """
        return FractionFieldElement(self.ring.zero(), self.ring.one(), self)


    def one(self) -> FractionFieldElement:
        """
        Returns:
            FractionFieldElement: '1' element of the algebra.
        """
        return FractionFieldElement(self.ring.one(), self.ring.one(), self)


    def random(self, size: int=None) -> FractionFieldElement:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            FractionFieldElement: Random element of the algebra.
        """
        if type(size) is int:
            numerator   = size
            denominator = size
        else:
            numerator   = size.numerator
            denominator = size.denominator

        return FractionFieldElement(self.ring.random(numerator), max(self.ring.one(), self.ring.random(denominator)), self)


    def shorthand(self) -> str:
        return f'Frac({self.ring})'


    def coerce(self, other: object) -> FractionFieldElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            FractionFieldElement: Coerced element.
        """
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
