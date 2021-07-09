from samson.math.algebra.rings.ring import Ring, RingElement
from samson.utilities.exceptions import CoercionException
from samson.math.general import random_int
from samson.math.map import Map
from types import FunctionType

_NEG_MAP = lambda e: -e

class Endomorphism(RingElement):

    def __init__(self, val: int, ring: Ring, post_map: FunctionType=None):
        """
        Parameters:
            val   (int): Value of the element.
            ring (Ring): Parent ring.
        """
        self.val = val
        self.post_map = post_map
        super().__init__(ring)


    def tinyhand(self) -> str:
        return str(self.val)


    def __reprdir__(self):
        return ['val', 'ring']


    def degree(self) -> int:
        return self.val.degree()


    def order(self) -> int:
        """
        The minimum number of times the element can be added to itself before reaching the additive identity.

        Returns:
            int: Order.
        """
        raise NotImplementedError


    def __call__(self, element):
        val = self.val(element)

        if self.post_map:
            val = self.post_map(val)
        
        return val


    def __elemadd__(self, other):
        # Mathematically, these checks aren't needed. However, this gives us the possibility
        # of not using a wrapper Map which would prevent negation and inversion.
        if not self:
            return -other

        elif not other:
            return self

        elif self == -other or other == -self:
            return self.ring.zero

        else:
            val = Map(self.ring.ring, self.ring.ring, lambda e: self(e) + other(e))
            return Endomorphism(val, self.ring)


    def __invert__(self):
        return Endomorphism(~self.val, self.ring)


    def __neg__(self) -> 'IntegerElement':
        try: 
            return Endomorphism(-self.val, self.ring)
        except TypeError:
            return Endomorphism(self.val, self.ring, _NEG_MAP)



class EndomorphismRing(Ring):

    def __init__(self, ring):
        self.ring = ring
        self.isomorphisms = ring.isomorphisms(ring)
        self.zero = self(lambda e: ring.zero)
        self.one  = self( [phi for phi in self.isomorphisms if phi.is_identity()][0])


    def __reprdir__(self):
        return ['ring']


    def characteristic(self) -> int:
        return NotImplementedError


    def order(self) -> int:
        return NotImplementedError


    def __hash__(self) -> int:
        return hash((self.__class__, self.ring))


    def shorthand(self) -> str:
        return f'End({self.ring})'


    def coerce(self, other: int) -> Endomorphism:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (int): Object to coerce.

        Returns:
            Endomorphism: Coerced element.
        """
        type_o = type(other)
        if type_o is Endomorphism and other.ring == self:
            return other

        elif issubclass(type_o, Map):
            return Endomorphism(other, self)

        elif issubclass(type_o, FunctionType):
            return Endomorphism(Map(self.ring, self.ring, other), self)

        raise CoercionException(self, other)


    def __eq__(self, other: 'IntegerRing') -> bool:
        return type(self) == type(other) and self.ring == other.ring


    def element_at(self, x: int) -> Endomorphism:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           Endomorphism: The `x`-th element.
        """
        return Endomorphism(self.isomorphisms[x], self)


    def random(self, size=None):
        return self[random_int(len(self.isomorphisms))]


End = EndomorphismRing
