from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.utilities.exceptions import CoercionException
from samson.math.general import is_prime, factor

class IntegerElement(RingElement):
    """
    Element of an `IntegerRing`.
    """

    def __init__(self, val: int, ring: Ring):
        """
        Parameters:
            val   (int): Value of the element.
            ring (Ring): Parent ring.
        """
        self.ring = ring
        self.val  = val


    def __repr__(self):
        return f"<IntegerElement: val={self.val}, ring={self.ring}>"


    def factor(self) -> list:
        return factor(self.val)

    def is_prime(self) -> list:
        return is_prime(self.val)


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return self.val

    @left_expression_intercept
    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegerElement(self.val + other.val, self.ring)

    @left_expression_intercept
    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegerElement(self.val - other.val, self.ring)

    def __mul__(self, other: object) -> object:
        gmul = self.ground_mul(other)
        if gmul:
            return gmul

        other = self.ring.coerce(other)
        return IntegerElement(self.val * other.val, self.ring)


    @left_expression_intercept
    def __divmod__(self, other: object) -> (object, object):
        other = self.ring.coerce(other)
        q, r = divmod(self.val, other.val)
        return IntegerElement(q, self.ring), IntegerElement(r, self.ring)

    @left_expression_intercept
    def __mod__(self, other: object) -> object:
        return divmod(self, other)[1]

    @left_expression_intercept
    def __floordiv__(self, other: object) -> object:
        return divmod(self, other)[0]

    __truediv__ = __floordiv__

    def __neg__(self) -> object:
        return IntegerElement(-self.val, self.ring)

    def __eq__(self, other: object) -> bool:
        if other is IntegerElement:
            other = other.val

        return self.val == other

    def __hash__(self):
        return super().__hash__()


class IntegerRing(Ring):
    """
    The ring of integers, Z.
    """

    @property
    def characteristic(self):
        return 0

    @property
    def order(self) -> int:
        from samson.math.symbols import oo
        return oo


    def __hash__(self) -> int:
        return hash(self.__class__)


    def zero(self) -> IntegerElement:
        """
        Returns:
            IntegerElement: '0' element of the algebra.
        """
        return IntegerElement(0, self)


    def one(self) -> IntegerElement:
        """
        Returns:
            IntegerElement: '1' element of the algebra.
        """
        return IntegerElement(1, self)


    def element_at(self, x: int) -> IntegerElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           IntegerElement: The `x`-th element.
        """
        return self(x)


    def __repr__(self):
        return f"<IntegerRing>"


    def shorthand(self) -> str:
        return 'ZZ'


    def coerce(self, other: int) -> IntegerElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (int): Object to coerce.
        
        Returns:
            IntegerElement: Coerced element.
        """
        if type(other) is int:
            return IntegerElement(other, self)

        elif type(other) is IntegerElement:
            return other

        raise CoercionException('Coercion failed')


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other)


ZZ = IntegerRing()
