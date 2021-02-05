from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.ring import left_expression_intercept
from samson.utilities.exceptions import CoercionException, NoSolutionException
import mpmath
import math

class RealElement(FieldElement):
    """
    Element of a `RealField`.
    """

    def __init__(self, val: FieldElement, field: Field):
        """
        Parameters:
            val     (MPF): Value of the element.
            field (Field): Parent field.
        """
        self.val   = val
        self.field = field


    def shorthand(self) -> str:
        return str(self.val)


    def tinyhand(self) -> str:
        return self.shorthand()


    def __hash__(self) -> int:
        return hash((self.val, self.field))



    @left_expression_intercept
    def __add__(self, other: 'RealElement') -> 'RealElement':
        other = self.ring.coerce(other)
        return self.field(self.val + other.val)


    @left_expression_intercept
    def __sub__(self, other: 'RealElement') -> 'RealElement':
        other = self.ring.coerce(other)
        return self + -other


    def __mul__(self, other: 'RealElement') -> 'RealElement':
        other = self.ring.coerce(other)
        return self.field(self.val * other.val)

    def __pow__(self, other: 'RealElement') -> 'RealElement':
        other = self.ring.coerce(other)
        return self.field(self.val**other.val)


    def __abs__(self):
        return self.field(abs(self.val))


    def __round__(self):
        a = abs(self)
        n = int(a) + ((a - int(a)) > 0.5)
        if self < 0:
            n = -n
        return n



    @left_expression_intercept
    def __mod__(self, other: 'RealElement') -> 'RealElement':
        other = self.ring.coerce(other)
        return RealElement(self.val % other.val, self.ring)


    def __invert__(self) -> 'RealElement':
        return self**-1


    def __neg__(self) -> 'RealElement':
        return self.field(-self.val)


    def __eq__(self, other: 'RealElement') -> bool:
        if type(other) is int:
            return self.val == other

        return type(self) == type(other) and self.val == other.val and self.field == other.field


    def _element_division(self, other: 'RingElement') -> 'RingElement':
        other = self.field(other)
        return self.field(self.val / other.val)



    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        return True


    def sqrt(self) -> 'RealElement':
        return self.field(self.field.ctx.sqrt(self.val))


    def kth_root(self, k:int) -> 'RealElement':
        if self < 0 and not k % 2:
            raise NoSolutionException

        return self**(self.field(1)/self.field(k))


    def get_ground(self) -> 'RealElement':
        return self


    def log(self, other: 'RealElement') -> 'RealElement':
        other = self.field(other)
        return self.field(self.field.ctx.log(self.val, other.val))


    def exp(self) -> 'RealElement':
        return self.field(self.field.ctx.exp(self.val))


    def ceil(self) -> 'RealElement':
        return self.field(math.ceil(self.val))


class RealField(Field):

    def __init__(self, prec: int=53, ctx: object=None):
        """
        Parameters:
            prec (int): Desired precision in bits.
        """
        self.prec = prec
        if ctx:
            self.ctx = ctx
        else:
            self.ctx     = mpmath.ctx_mp.MPContext()
            self.ctx.dps = math.ceil(prec/math.log(10, 2))

        self.zero = self(0)
        self.one  = self(1)


    def __reprdir__(self):
        return ['prec']



    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        from samson.math.symbols import oo
        return oo


    def shorthand(self) -> str:
        return 'RR'


    def coerce(self, other: object) -> RealElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            RealElement: Coerced element.
        """
        if hasattr(other, 'ring') and other.ring == self:
            return other

        else:
            try:
                return RealElement(self.ctx.mpf(other), self)
            except ValueError as e:
                raise CoercionException(other) from e



    def element_at(self, x: int) -> RealElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           RealElement: The `x`-th element.
        """
        return self(x)


    def __eq__(self, other: 'RealField') -> bool:
        return type(self) == type(other) and self.prec == other.prec

    def __hash__(self) -> int:
        return hash((self.prec, self.__class__))


    def random(self, size: object=None) -> object:
        """
        Generate a random element.

        Parameters:
            size (int/FieldElement): The maximum ordinality/element (non-inclusive).
    
        Returns:
            FieldElement: Random element of the algebra.
        """
        from samson.math.general import random_int

        if not size:
            size = 2**self.prec

        n, d = self(size).val.as_integer_ratio()
        return self(random_int(n))/self(max(1, random_int(d)))


RR = RealField()
