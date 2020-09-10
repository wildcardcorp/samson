from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.utilities.exceptions import CoercionException
from samson.auxiliary.lazy_loader import LazyLoader
from samson.math.general import is_prime, kth_root
from samson.math.factorization.general import factor
from samson.math.factorization.factors import Factors
from samson.math.symbols import oo

_all_mod = LazyLoader('all_mod', globals(), 'samson.math.all')

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


    def tinyhand(self) -> str:
        return str(self.val)


    def factor(self, **kwargs) -> dict:
        return Factors({ZZ(k):v for k,v in factor(self.val, **kwargs).items()})


    def is_prime(self) -> bool:
        return is_prime(self.val)


    def is_irreducible(self) -> bool:
        return self.is_prime()


    def kth_root(self, k: int) -> 'IntegerElement':
        return ZZ(kth_root(int(self), k))


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


    @property
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


    @left_expression_intercept
    def __add__(self, other: 'IntegerElement') -> 'IntegerElement':
        other = self.ring.coerce(other)
        return IntegerElement(self.val + other.val, self.ring)


    @left_expression_intercept
    def __sub__(self, other: 'IntegerElement') -> 'IntegerElement':
        other = self.ring.coerce(other)
        return IntegerElement(self.val - other.val, self.ring)


    def __mul__(self, other: 'IntegerElement') -> 'IntegerElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul

        other = self.ring.coerce(other)
        return IntegerElement(self.val * other.val, self.ring)


    @left_expression_intercept
    def __divmod__(self, other: 'IntegerElement') -> ('IntegerElement', 'IntegerElement'):
        other = self.ring.coerce(other)
        q, r = divmod(self.val, other.val)
        return IntegerElement(q, self.ring), IntegerElement(r, self.ring)


    @left_expression_intercept
    def __mod__(self, other: 'IntegerElement') -> 'IntegerElement':
        return divmod(self, other)[1]


    @left_expression_intercept
    def __floordiv__(self, other: 'IntegerElement') -> 'IntegerElement':
        return divmod(self, other)[0]


    def __neg__(self) -> 'IntegerElement':
        return IntegerElement(-self.val, self.ring)


    def __eq__(self, other: 'IntegerElement') -> bool:
        if other is IntegerElement:
            other = other.val

        return self.val == other


    def __hash__(self):
        return super().__hash__()


class IntegerRing(Ring):
    """
    The ring of integers, Z.
    """

    def __init__(self):
        self.zero = IntegerElement(0, self)
        self.one  = IntegerElement(1, self)


    @property
    def characteristic(self) -> int:
        return 0

    @property
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


    def __repr__(self):
        return "<IntegerRing>"


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

        elif other.ring == _all_mod.QQ and other.denominator == ZZ.one:
            return other.numerator

        raise CoercionException(self, other)


    def __eq__(self, other: 'IntegerRing') -> bool:
        return type(self) == type(other)


ZZ = IntegerRing()
