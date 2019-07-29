from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import mod_inv, fast_mul

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
        self.ring = ring
        self.val  = val % self.ring.quotient


    def __repr__(self):
        return f"<QuotientElement: val={self.val}, ring={self.ring}>"


    def shorthand(self) -> str:
        return self.val.shorthand()


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return self.val.ordinality()


    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val + other.val) % self.ring.quotient, self.ring)

    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val - other.val) % self.ring.quotient, self.ring)

    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return fast_mul(self, other)

        other = self.ring.coerce(other)
        return QuotientElement((self.val * other.val) % self.ring.quotient, self.ring)

    def __mod__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val % other.val) % self.ring.quotient, self.ring)

    def __invert__(self) -> object:
        return QuotientElement(mod_inv(self.val, self.ring.quotient), self.ring)

    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self * ~other

    def __floordiv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val // other.val) % self.ring.quotient, self.ring)

    def __neg__(self) -> object:
        return QuotientElement((-self.val) % self.ring.quotient, self.ring)


    def __eq__(self, other: object) -> bool:
        if type(other) is int:
            return self.val == other

        return type(self) == type(other) and self.val == other.val and self.ring == other.ring

    def __hash__(self) -> bool:
        return hash(self.val) + hash(self.ring)


    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        from samson.math.general import gcd
        return gcd(self.val, self.ring.quotient) == self.ring.ring.one()


class QuotientRing(Ring):
    """
    Ring built from an underlying ring and quotient.

    Examples:
        >>> from samson.math.all import *
        >>> quot_ring = ZZ/ZZ(53)
        >>> quot_ring(5) * ~quot_ring(4)
        <QuotientElement: val=ZZ(41), ring=ZZ/ZZ(53)>

    """

    def __init__(self, quotient: RingElement, ring: Ring):
        """
        Parameters:
            quotient (RingElement): Element from the underlying ring.
            ring            (Ring): Underlying ring.
        """
        assert(quotient.ring == ring)
        self.ring     = ring
        self.quotient = quotient


    def __repr__(self):
        return f"<QuotientRing ring={self.ring}, quotient={self.quotient}>"


    @property
    def characteristic(self) -> int:
        from samson.math.algebra.rings.integer_ring import IntegerElement
        from samson.math.polynomial import Polynomial

        if type(self.quotient) is IntegerElement:
            return int(self.quotient)

        elif type(self.quotient) is Polynomial:
            return self.quotient.ring.ring.characteristic


    @property
    def p(self) -> int:
        from samson.math.algebra.rings.integer_ring import IntegerElement
        if type(self.quotient) is IntegerElement:
            return int(self.quotient)


    @property
    def order(self) -> int:
        from samson.math.algebra.rings.integer_ring import IntegerElement
        from samson.math.polynomial import Polynomial

        if type(self.quotient) is IntegerElement and self.quotient.is_prime():
            return int(self.quotient)

        elif type(self.quotient) is Polynomial and self.quotient.is_prime():
            return self.characteristic**self.quotient.degree()

        else:
            raise NotImplementedError


    def zero(self) -> QuotientElement:
        """
        Returns:
            QuotientElement: '0' element of the algebra.
        """
        return QuotientElement(self.ring.zero(), self)


    def one(self) -> QuotientElement:
        """
        Returns:
            QuotientElement: '1' element of the algebra.
        """
        return QuotientElement(self.ring.one(), self)


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}/{self.quotient.shorthand()}'


    def coerce(self, other: int) -> QuotientElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            QuotientElement: Coerced element.
        """
        if type(other) is not QuotientElement:
            other = QuotientElement(self.ring.coerce(other), self)
        return other


    def element_at(self, x: int) -> QuotientElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           QuotientElement: The `x`-th element.
        """
        return self(self.ring.element_at(x))


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.quotient == other.quotient

    def __call__(self, args):
        return QuotientElement(self.ring(args), self)

    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))
