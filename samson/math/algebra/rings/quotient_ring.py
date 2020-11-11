from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
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


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return self.val.ordinality()


    def __call__(self, x: int) -> RingElement:
        return self.val(x)


    @left_expression_intercept
    def __add__(self, other: 'QuotientElement') -> 'QuotientElement':
        other = self.ring.coerce(other)
        return QuotientElement(self.val + other.val, self.ring)


    @left_expression_intercept
    def __sub__(self, other: 'QuotientElement') -> 'QuotientElement':
        other = self.ring.coerce(other)
        return QuotientElement(self.val - other.val, self.ring)


    def __mul__(self, other: 'QuotientElement') -> 'QuotientElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul

        other = self.ring.coerce(other)
        return QuotientElement(self.val * other.val, self.ring)


    @left_expression_intercept
    def __mod__(self, other: 'QuotientElement') -> 'QuotientElement':
        other = self.ring.coerce(other)
        return QuotientElement(self.val % other.val, self.ring)

    def __invert__(self) -> 'QuotientElement':
        return QuotientElement(mod_inv(self.val, self.ring.quotient), self.ring)


    @left_expression_intercept
    def __truediv__(self, other: 'QuotientElement') -> 'QuotientElement':
        other = self.ring.coerce(other)
        return self * ~other


    @left_expression_intercept
    def __floordiv__(self, other: 'QuotientElement') -> 'QuotientElement':
        other = self.ring.coerce(other)
        return QuotientElement(self.val // other.val, self.ring)

    def __divmod__(self, other):
        return self // other, self % other


    def __neg__(self) -> 'QuotientElement':
        return QuotientElement((-self.val), self.ring)


    def __eq__(self, other: 'QuotientElement') -> bool:
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
        return gcd(self.val, self.ring.quotient) == self.ring.ring.one


    def sqrt(self) -> 'QuotientElement':
        from samson.math.algebra.rings.integer_ring import ZZ

        if self.ring.ring == ZZ:
            from samson.math.general import tonelli
            return self.ring(tonelli(int(self), int(self.ring.quotient)))
        else:
            return self.kth_root(2)



class QuotientRing(Ring):
    """
    Ring built from an underlying ring and quotient.

    Examples:
        >>> from samson.math.all import *
        >>> quot_ring = ZZ/ZZ(53)
        >>> quot_ring(5) * ~quot_ring(4)
        <QuotientElement: val=41, ring=ZZ/ZZ(53)>

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

        self.zero = QuotientElement(self.ring.zero, self)
        self.one  = QuotientElement(self.ring.one, self)


    def __repr__(self):
        return f"<QuotientRing: ring={self.ring}, quotient={self.quotient}>"


    @property
    def characteristic(self) -> int:
        from samson.math.algebra.rings.integer_ring import IntegerElement
        from samson.math.polynomial import Polynomial

        quotient = self.quotient.get_ground()

        if type(quotient) is IntegerElement:
            return int(quotient)

        elif type(quotient) is Polynomial:
            return quotient.ring.ring.characteristic

        else:
            raise NotImplementedError


    @property
    def p(self) -> int:
        from samson.math.algebra.rings.integer_ring import IntegerElement
        if type(self.quotient) is IntegerElement:
            return int(self.quotient)


    @property
    def order(self) -> int:
        from samson.math.algebra.rings.integer_ring import IntegerElement
        from samson.math.polynomial import Polynomial

        quotient = self.quotient.get_ground()
        type_o   = type(quotient)

        if type_o is IntegerElement:
            return int(quotient)

        elif type_o is Polynomial:
            return quotient.ring.ring.order**quotient.degree()

        else:
            raise NotImplementedError



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


    def __eq__(self, other: 'QuotientElement') -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.quotient == other.quotient

    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


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
        from samson.math.general import random_int

        if not size:
            size = self.order-1

        if type(size) is int:
            return self[random_int(size)]
        else:
            return self[random_int(size.ordinality())]
