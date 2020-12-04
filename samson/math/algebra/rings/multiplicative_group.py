from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.math.general import totient, index_calculus
from samson.math.symbols import oo
from samson.utilities.runtime import RUNTIME

class MultiplicativeGroupElement(RingElement):
    """
    Element of a `MultiplicativeGroup`.
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
        return f"<MultiplicativeGroupElement: val={self.val}, ring={self.ring}>"


    @left_expression_intercept
    def __add__(self, other: 'MultiplicativeGroupElement') -> 'MultiplicativeGroupElement':
        other = self.ring.coerce(other)
        return MultiplicativeGroupElement(self.val * other.val, self.ring)


    @left_expression_intercept
    def __sub__(self, other: 'MultiplicativeGroupElement') -> 'MultiplicativeGroupElement':
        other = self.ring.coerce(-other)
        return MultiplicativeGroupElement(self.val * other.val, self.ring)


    def __mul__(self, other: 'MultiplicativeGroupElement') -> 'MultiplicativeGroupElement':
        other = int(other)
        if self.ring.order and self.ring.order != oo:
            other %= self.ring.order

        return MultiplicativeGroupElement(self.val ** other, self.ring)


    def __neg__(self) -> 'MultiplicativeGroupElement':
        return MultiplicativeGroupElement(~self.val, self.ring)


    @left_expression_intercept
    def __truediv__(self, other: 'MultiplicativeGroupElement') -> int:
        return self.val.log(other.val)


    __floordiv__ = __truediv__


    def ordinality(self) -> int:
        return self.val.ordinality() - 1


    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        return self.val.is_invertible()


    def is_primitive_root(self) -> bool:
        """
        Determines if the element is a primitive root.

        Returns:
            bool: Whether the element is a primitive root.
        """
        return self.order == self.ring.order


    def _plog(self, base: 'RingElement', order: int) -> int:
        """
        Internal function for 'prime logarithm'. Called by Pohlig-Hellman
        to allow rings to define their own subalgorithms.
        """
        if order.bit_length() >= RUNTIME.index_calculus_supremacy:
            from samson.math.algebra.rings.integer_ring import ZZ

            if hasattr(self.ring.ring, 'quotient') and self.ring.ring.ring == ZZ:
                return index_calculus(base, self, order=order)

        return super()._plog(base, order)



class MultiplicativeGroup(Ring):
    """
    The group of a ring under multiplication. This basically just 'promotes' multiplication to the addition operator.

    Examples:
        >>> from samson.math.all import *
        >>> a, b = 36, 9
        >>> ring = ZZ/ZZ(53)
        >>> mul_ring = ring.mul_group()
        >>> g = mul_ring(2)
        >>> (g*a)*(g*b) # Perform Diffie-Hellman
        <MultiplicativeGroupElement: val=15, ring=ZZ/ZZ(53)*>

    """

    def __init__(self, ring: Ring):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring        = ring
        self.order_cache = None

        self.zero = MultiplicativeGroupElement(self.ring.one, self)
        self.one  = self.zero


    @property
    def characteristic(self) -> int:
        return self.ring.characteristic


    @property
    def order(self) -> int:
        if not self.order_cache:
            from samson.math.algebra.rings.quotient_ring import QuotientRing
            from samson.math.algebra.rings.integer_ring import IntegerElement
            from samson.math.algebra.fields.finite_field import FiniteField
            from samson.math.polynomial import Polynomial

            if type(self.ring) is QuotientRing:
                quotient = self.ring.quotient

                if type(quotient) is IntegerElement:
                    self.order_cache = totient(int(quotient))

                elif type(quotient) is Polynomial:
                    if quotient.is_prime():
                        self.order_cache = int(quotient) - 1

                    else:
                        self.order_cache = totient(int(quotient))

                else:
                    raise NotImplementedError()

            elif type(self.ring) is FiniteField:
                self.order_cache = self.ring.order-1


            elif self.ring.order == oo:
                self.order_cache = oo

            else:
                raise NotImplementedError()

        return self.order_cache



    def __repr__(self):
        return f"<MultiplicativeGroup: ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring}*'


    def coerce(self, other: object) -> MultiplicativeGroupElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            MultiplicativeGroupElement: Coerced element.
        """
        if type(other) is not MultiplicativeGroupElement or other.ring.ring != self.ring:
            return MultiplicativeGroupElement(self.ring(other), self)
        else:
            return other


    def element_at(self, x: int) -> MultiplicativeGroupElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           MultiplicativeGroupElement: The `x`-th element.
        """
        return self(self.ring[x+1])


    def __eq__(self, other: 'MultiplicativeGroup') -> bool:
        return type(self) == type(other) and self.ring == other.ring


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def random(self, size: object=None) -> object:
        return self(self.ring.random(size))
