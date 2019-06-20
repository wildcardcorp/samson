from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import mod_inv

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


    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val + other.val) % self.ring.quotient, self.ring)

    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val - other.val) % self.ring.quotient, self.ring)

    def __mul__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val * other.val) % self.ring.quotient, self.ring)

    def __mod__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val % other.val) % self.ring.quotient, self.ring)

    def __invert__(self) -> object:
        return QuotientElement(mod_inv(self.val, self.ring.quotient, zero=self.ring.ring.zero(), one=self.ring.ring.one()), self.ring)

    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self * ~other

    def __floordiv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val // other.val) % self.ring.quotient, self.ring)

    def __neg__(self) -> object:
        return QuotientElement((-self.val) % self.ring.quotient, self.ring)


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
        from samson.math.algebra.rings.polynomial_ring import PolynomialElement

        if type(self.quotient) is IntegerElement:
            return int(self.quotient)
        elif type(self.quotient) is PolynomialElement:
            return self.quotient.ring.field.characteristic


    @property
    def p(self) -> int:
        from samson.math.algebra.rings.integer_ring import IntegerElement
        if type(self.quotient) is IntegerElement:
            return int(self.quotient)


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


    def random(self, size: int=None) -> QuotientElement:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            QuotientElement: Random element of the algebra.
        """
        return QuotientElement(self.ring.random(size or self.characteristic), self)


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


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.quotient == other.quotient

    def __call__(self, args):
        return QuotientElement(self.ring(args), self)

    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))
