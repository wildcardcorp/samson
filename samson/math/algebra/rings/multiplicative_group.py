from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.math.general import totient, factor
from samson.utilities.exceptions import SearchspaceExhaustedException
from itertools import combinations
from functools import reduce

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


    @property
    def order(self) -> int:
        """
        The minimum number of times the element can be added to itself before reaching the additive identity.

        Returns:
            int: Order.
        """
        expanded_factors = [1] + [item for fac, num in factor(self.ring.order).items() for item in [fac]*num]
        all_orders = []

        for product_size in range(1, len(expanded_factors)+1):
            for combination in set(combinations(expanded_factors, product_size)):
                product = reduce(int.__mul__, combination, 1)
                if self*product == self.ring.one():
                    all_orders.append(product)

        return min(all_orders)



    @left_expression_intercept
    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return MultiplicativeGroupElement(self.val * other.val, self.ring)

    @left_expression_intercept
    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return MultiplicativeGroupElement(self.val / other.val, self.ring)

    def __mul__(self, other: object) -> object:
        other = int(other)
        if self.ring.order_cache:
            other %= self.ring.order_cache

        return MultiplicativeGroupElement(self.val ** other, self.ring)

    def __neg__(self) -> object:
        return MultiplicativeGroupElement(~self.val, self.ring)


    @left_expression_intercept
    def __truediv__(self, other: object) -> object:
        from samson.math.general import pohlig_hellman

        g = self.ring.coerce(other)
        return pohlig_hellman(g, self, self.ring.order)


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
        <MultiplicativeGroupElement: val=ZZ(15), ring=ZZ/ZZ(53)*>

    """

    def __init__(self, ring: Ring):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring        = ring
        self.order_cache = None


    @property
    def characteristic(self) -> int:
        return self.ring.characteristic


    @property
    def order(self) -> int:
        from samson.math.algebra.rings.quotient_ring import QuotientRing
        from samson.math.algebra.rings.integer_ring import IntegerElement
        from samson.math.polynomial import Polynomial
        from samson.math.symbols import oo

        if not self.order_cache:
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

            elif self.ring.order == oo:
                self.order_cache = oo

            else:
                raise NotImplementedError()

        return self.order_cache


    def zero(self) -> MultiplicativeGroupElement:
        """
        Returns:
            MultiplicativeGroupElement: '0' element of the algebra.
        """
        return MultiplicativeGroupElement(self.ring.one(), self)


    def one(self) -> MultiplicativeGroupElement:
        """
        Returns:
            MultiplicativeGroupElement: '1' element of the algebra.
        """
        return self.zero()


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
        from samson.math.algebra.rings.quotient_ring import QuotientRing

        if type(other) is int and type(self.ring) is QuotientRing:
            other %= self.ring.quotient

        if type(other) is not MultiplicativeGroupElement:
            other = MultiplicativeGroupElement(self.ring.coerce(other), self)
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

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def find_gen(self) -> MultiplicativeGroupElement:
        """
        Finds a generator of the MultiplicativeGroup.

        Returns:
            MultiplicativeGroupElement: A generator element.
        """
        for i in range(2, self.order):
            possible_gen = self[i]
            if possible_gen * self.order == self.one() and possible_gen.order == self.order:
                return possible_gen

        raise SearchspaceExhaustedException("Unable to find generator")
