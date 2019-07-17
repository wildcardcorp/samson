from samson.math.algebra.rings.ring import Ring, RingElement

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


    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return MultiplicativeGroupElement(self.val * other.val, self.ring)

    def __radd__(self, other: object) -> object:
        return self.ring.coerce(other) + self

    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return MultiplicativeGroupElement(self.val / other.val, self.ring)

    def __rsub__(self, other: object) -> object:
        return self.ring.coerce(other) - self

    def __mul__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return MultiplicativeGroupElement(self.val ** int(other.val), self.ring)

    def __neg__(self) -> object:
        return MultiplicativeGroupElement(~self.val, self.ring)



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
        self.ring = ring


    @property
    def characteristic(self):
        return self.ring.characteristic


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


    def random(self, size: int=None) -> MultiplicativeGroupElement:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            MultiplicativeGroupElement: Random element of the algebra.
        """
        return MultiplicativeGroupElement(self.ring.random(size), self)


    def __repr__(self):
        return f"<MultiplicativeGroup ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring}*'


    def coerce(self, other: int) -> MultiplicativeGroupElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            MultiplicativeGroupElement: Coerced element.
        """
        if type(other) is not MultiplicativeGroupElement:
            other = MultiplicativeGroupElement(self.ring.coerce(other), self)
        return other


    def element_at(self, x: int) -> MultiplicativeGroupElement:
        return self(self.ring[x+1])

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))
