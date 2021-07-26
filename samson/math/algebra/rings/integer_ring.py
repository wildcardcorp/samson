from samson.math.algebra.rings.ring import Ring, RingElement
from samson.utilities.exceptions import CoercionException, NoSolutionException
from samson.math.general import is_prime, kth_root
from samson.math.factorization.general import factor
from samson.math.factorization.factors import Factors
from samson.math.symbols import oo
from functools import lru_cache

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
        self.val = val
        super().__init__(ring)


    # Explicitly define for speed
    def __elemadd__(self, other: 'RingElement') -> 'RingElement':
        return IntegerElement(self.val + other.val, self.ring)


    def __elemmul__(self, other: 'RingElement') -> 'RingElement':
        return IntegerElement(self.val * other.val, self.ring)


    def __elemmod__(self, other: 'RingElement') -> 'RingElement':
        return IntegerElement(self.val % other.val, self.ring)


    def tinyhand(self) -> str:
        return str(self.val)


    def factor(self, **kwargs) -> dict:
        return Factors({ZZ(k):v for k,v in factor(self.val, **kwargs).items()})


    def is_prime(self) -> bool:
        return is_prime(self.val)


    def is_irreducible(self) -> bool:
        return self.is_prime()


    def kth_root(self, k: int, strict: bool=True) -> 'IntegerElement':
        root = kth_root(int(self), k)
        if strict and self != root**k:
            raise NoSolutionException

        return ZZ(root)


    def is_square(self) -> bool:
        return self.kth_root(2, strict=False)**2 == self


    def valuation(self, p: int) -> int:
        from samson.math.symbols import oo

        if not self:
            return oo

        v = -1
        r = 0
        int_self = int(self)
        while not r:
            v += 1
            int_self, r = divmod(int_self, p)

        return v


    def order(self) -> int:
        """
        The minimum number of times the element can be added to itself before reaching the additive identity.

        Returns:
            int: Order.
        """
        return oo


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return self.val


    def ground_mul(self, other: 'IntegerElement') -> 'IntegerElement':
        try:
            return IntegerElement(self.val * int(other), self.ring)
        except Exception:
            pass


    def __neg__(self) -> 'IntegerElement':
        return IntegerElement(-self.val, self.ring)


    def __eq__(self, other: 'IntegerElement') -> bool:
        if type(other) is IntegerElement:
            other = other.val

        return self.val == other


    def __hash__(self) -> int:
        return super().__hash__()


class IntegerRing(Ring):
    """
    The ring of integers, Z.
    """

    def __init__(self):
        self.zero = IntegerElement(0, self)
        self.one  = IntegerElement(1, self)


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def __hash__(self) -> int:
        return hash(self.__class__)


    def element_at(self, x: int) -> IntegerElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           IntegerElement: The `x`-th element.
        """
        return self(x)


    def __reprdir__(self):
        return []


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
        type_o = type(other)

        if type_o is IntegerElement:
            return other

        elif type_o is int:
            return IntegerElement(other, self)

        elif other.ring == _get_QQ() and other.denominator == ZZ.one:
            return other.numerator

        try:
            if other.ring(int(other)) == other:
                return self.coerce(int(other))
        except:
            pass

        raise CoercionException(self, other)


    def __eq__(self, other: 'IntegerRing') -> bool:
        return type(self) == type(other)


ZZ = IntegerRing()

@lru_cache(1)
def _get_QQ():
    return ZZ.fraction_field()
