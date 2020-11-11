from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.ring import Ring, left_expression_intercept
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import gcd
from fractions import Fraction


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

        if denominator == field.ring.zero:
            raise ZeroDivisionError

        self.numerator   = numerator
        self.denominator = denominator
        self.field       = field

        if self.ring.precision:
            self.trim_to_precision()



    def __repr__(self):
        return f"<FractionFieldElement: numerator={self.numerator}, denominator={self.denominator}, ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.field.shorthand()}({self.numerator}/{self.denominator})'


    def tinyhand(self) -> str:
        return f'{self.numerator.tinyhand()}{"/" + str(self.denominator.tinyhand()) if self.denominator != self.ring.ring.one else ""}'


    def __hash__(self):
        return hash((self.numerator, self.denominator, self.field))

    def __eq__(self, other: 'FractionFieldElement'):
        other = self.ring.coerce(other)
        return type(self) == type(other) and self.numerator * other.denominator == self.denominator * other.numerator


    def __call__(self, x: int) -> 'RingElement':
        return self.numerator(x) / self.denominator(x)


    def valuation(self, p: int) -> int:
        from samson.math.symbols import oo

        if not self:
            return oo

        return self.numerator.valuation(p) - self.denominator.valuation(p)


    def sqrt(self) -> 'FractionFieldElement':
        if type(self.ring.ring).__name__ == 'IntegerRing':
            from samson.math.general import kth_root_qq
            return kth_root_qq(self, 2)
        else:
            return FractionFieldElement(self.numerator.sqrt(), self.denominator.sqrt(), self.ring)


    def trim_to_precision(self) -> 'FractionFieldElement':
        """
        WARNING: Side effect based.

        Attempts to trim `self` so that the error is less than `precision`.
        """
        precision      = self.ring.precision
        precision_type = self.ring.precision_type

        if precision_type == 'relative':
            if self.numerator != self.denominator and self.ring.ring.one not in [self.numerator, self.denominator]:
                if self.numerator > self.denominator:
                    q,r = divmod(self.numerator, self.denominator)
                    den = self.ring.ring.one
                    num = q

                    compare_num = r
                    compare_den = abs(q)


                elif self.numerator < self.denominator:
                    q,r = divmod(self.denominator, self.numerator)
                    num = self.ring.ring.one
                    den = q

                    compare_num = r
                    compare_den = self.denominator

                if compare_num * precision.denominator < precision.numerator * compare_den:
                    self.numerator   = num
                    self.denominator = den
        else:
            if self.denominator > precision:
                q,r = divmod(self.numerator, self.denominator)
                c   = self.ring(r / self.denominator * precision)

                self.numerator   = q * precision + c.numerator // c.denominator
                self.denominator = precision


    def gcd(self, other):
        from samson.math.general import lcm
        return self.ring((self.numerator.gcd(other.numerator), lcm(self.denominator, other.denominator)))


    @left_expression_intercept
    def __add__(self, other: 'FractionFieldElement') -> 'FractionFieldElement':
        other = self.ring.coerce(other)
        return FractionFieldElement(self.numerator * other.denominator + self.denominator * other.numerator, self.denominator * other.denominator, self.ring)


    @left_expression_intercept
    def __sub__(self, other: 'FractionFieldElement') -> 'FractionFieldElement':
        other = self.ring.coerce(other)
        return self + (-other)


    def __mul__(self, other: 'FractionFieldElement') -> 'FractionFieldElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul

        other = self.ring.coerce(other)
        return FractionFieldElement(self.numerator * other.numerator, self.denominator * other.denominator, self.ring)


    @left_expression_intercept
    def __truediv__(self, other: 'FractionFieldElement') -> 'FractionFieldElement':
        return self * (~self.ring.coerce(other))


    __floordiv__ = __truediv__


    def __neg__(self) -> 'FractionFieldElement':
        return FractionFieldElement(-self.numerator, self.denominator, self.ring)

    def __invert__(self) -> 'FractionFieldElement':
        if not self:
            raise ZeroDivisionError

        return FractionFieldElement(self.denominator, self.numerator, self.ring)


    def __float__(self):
        return int(self.numerator) / int(self.denominator)

    def __int__(self):
        return int(self.numerator) // int(self.denominator)

    def __round__(self):
        q,r = divmod(self.numerator, self.denominator)
        R = self.ring.ring
        return q + (R.one if r*2 >= self.denominator else R.zero)



    def __lt__(self, other: 'FractionFieldElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.numerator * other.denominator < other.numerator * self.denominator


    def __gt__(self, other: 'FractionFieldElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.numerator * other.denominator > other.numerator * self.denominator


class FractionField(Field):
    """
    Fraction field over a ring.

    Examples:
        >>> from samson.math.algebra.rings.integer_ring import IntegerRing
        >>> QQ = FractionField(IntegerRing())
        >>> assert QQ(5) * QQ((1, 5)) == QQ.one

    """

    def __init__(self, ring: Ring, simplify: bool=True):
        """
        Parameters:
            ring     (Ring): Underlying ring.
            simplify (bool): Whether or not to simplify the fraction.
        """
        self.ring      = ring
        self.simplify  = simplify
        self.precision = None
        self.precision_type = None

        self.zero = FractionFieldElement(self.ring.zero, self.ring.one, self)
        self.one  = FractionFieldElement(self.ring.one, self.ring.one, self)


    def __repr__(self):
        return f"<FractionField: ring={self.ring}>"


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def __eq__(self, other: 'FractionField'):
        return type(self) == type(other) and self.ring == other.ring

    @property
    def characteristic(self):
        return self.ring.characteristic


    @property
    def order(self) -> int:
        return self.ring.order**2


    def set_precision(self, precision: FractionFieldElement, precision_type: str='absolute'):
        """
        Sets the element used for determine whether a trim is acceptable.
        """
        self.precision = precision
        self.precision_type = precision_type


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

        return FractionFieldElement(self.ring.random(numerator), max(self.ring.one, self.ring.random(denominator)), self)


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
        type_other = type(other)
        if type_other is FractionFieldElement:
            return other

        elif type_other is float and self.ring == ZZ:
            frac = Fraction(other)
            result = (self.ring.coerce(frac.numerator), self.ring.coerce(frac.denominator))

        elif type_other is tuple:
            if len(other) < 2:
                denom = self.ring.one
            else:
                denom = self.ring.coerce(other[1])

            result = (self.ring.coerce(other[0]), denom)
        else:
            result = (self.ring.coerce(other), self.ring.one)


        return FractionFieldElement(*result, self)
