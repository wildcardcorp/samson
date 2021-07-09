from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import mod_inv, xgcd, gcd, tonelli, generalized_eulers_criterion, ResidueSymbol, random_int
from samson.utilities.exceptions import CoercionException

from samson.auxiliary.lazy_loader import LazyLoader
_integer_ring = LazyLoader('_integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')
_poly         = LazyLoader('_poly', globals(), 'samson.math.polynomial')

class QuotientElement(RingElement):
    """
    Element of a `QuotientRing`.
    """

    def __init__(self, val: RingElement, ring: Ring):
        """
        Parameters:
            val (RingElement): Value of the element.
            ring       (Ring): Parent ring.
        """
        super().__init__(ring)
        self.val = val % self.ring.quotient


    def __reprdir__(self):
        return ['val', 'ring']

    def shorthand(self) -> str:
        return self.val.shorthand()


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return self.val.ordinality()


    def __call__(self, x: int) -> RingElement:
        return self.val(x)


    # We explicitly include these operators to prevent a ring coercion (speed reasons)
    def __elemadd__(self, other: 'RingElement') -> 'RingElement':
        return QuotientElement(self.val + other.val, self.ring)


    def __elemmul__(self, other: 'RingElement') -> 'RingElement':
        return QuotientElement(self.val * other.val, self.ring)


    def __elemmod__(self, other: 'RingElement') -> 'RingElement':
        return QuotientElement(self.val % other.val, self.ring)


    def __invert__(self) -> 'QuotientElement':
        return QuotientElement(mod_inv(self.val, self.ring.quotient), self.ring)


    def __neg__(self) -> 'QuotientElement':
        return QuotientElement(-self.val, self.ring)


    def __eq__(self, other: 'QuotientElement') -> bool:
        try:
            other = self.ring(other)
            return self.val == other.val and self.ring == other.ring
        except CoercionException:
            return False


    def __hash__(self) -> bool:
        return hash((self.val, self.ring))


    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        return gcd(self.val, self.ring.quotient) == self.ring.ring.one


    def sqrt(self) -> 'QuotientElement':
        ZZ = _integer_ring.ZZ

        if self.ring.ring == ZZ and self.ring.is_field():
            return self.ring(tonelli(int(self), int(self.ring.quotient)))
        else:
            return self.kth_root(2)


    def is_square(self) -> bool:
        ZZ = _integer_ring.ZZ

        if self.ring.ring == ZZ:
            return generalized_eulers_criterion(int(self), 2, int(self.ring.quotient)) != ResidueSymbol.DOES_NOT_EXIST

        else:
            return super().is_square()



    def partial_inverse(self):
        d, n, _ = xgcd(self.val, self.ring.quotient)
        return n, d



class QuotientRing(Ring):
    """
    Ring built from an underlying ring and quotient.

    Examples:
        >>> from samson.math.all import *
        >>> quot_ring = ZZ/ZZ(53)
        >>> quot_ring(5) * ~quot_ring(4)
        <QuotientElement: val=41, ring=ZZ/(ZZ(53))>

    """

    def __init__(self, quotient: RingElement, ring: Ring):
        """
        Parameters:
            quotient (RingElement): Element from the underlying ring.
            ring            (Ring): Underlying ring.
        """
        assert(quotient.ring == ring)
        super().__init__()
        self.ring     = ring
        self.quotient = quotient

        self.zero = QuotientElement(self.ring.zero, self)
        self.one  = QuotientElement(self.ring.one, self)


    def __reprdir__(self):
        return ['ring', 'quotient']


    def characteristic(self) -> int:
        IntegerElement = _integer_ring.IntegerElement
        Polynomial = _poly.Polynomial

        quotient = self.quotient.get_ground()

        if type(quotient) is IntegerElement:
            return int(quotient)

        elif type(quotient) is Polynomial:
            return quotient.ring.ring.characteristic()

        else:
            raise NotImplementedError


    @property
    def p(self) -> int:
        IntegerElement = _integer_ring.IntegerElement
        if type(self.quotient) is IntegerElement:
            return int(self.quotient)



    def order(self) -> int:
        IntegerElement = _integer_ring.IntegerElement
        Polynomial = _poly.Polynomial

        quotient = self.quotient.get_ground()
        type_o   = type(quotient)

        if type_o is IntegerElement:
            return int(quotient)

        elif type_o is Polynomial:
            return quotient.ring.ring.order()**quotient.degree()

        else:
            raise NotImplementedError



    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}/({self.quotient.shorthand()})'


    def coerce(self, other: int) -> QuotientElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            QuotientElement: Coerced element.
        """
        if hasattr(other, 'ring') and other.ring == self:
            return other
        else:
            return QuotientElement(self.ring(other), self)



    def element_at(self, x: int) -> QuotientElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           QuotientElement: The `x`-th element.
        """
        return self(self.ring.element_at(x))


    def __eq__(self, other: 'QuotientRing') -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.quotient == other.quotient

    def __hash__(self) -> int:
        return hash((self.ring, self.__class__, self.quotient))


    def is_field(self) -> bool:
        return self.quotient.is_irreducible()


    def random(self, size: object=None) -> object:
        """
        Generate a random element.

        Parameters:
            size (int/RingElement): The maximum ordinality/element (non-inclusive).

        Returns:
            RingElement: Random element of the algebra.
        """
        if not size:
            size = self.order()-1

        if type(size) is int:
            return self[random_int(size)]
        else:
            r = self[random_int(size.ordinality())]
            while r >= size:
                r = self[random_int(size.ordinality())]
            return r
