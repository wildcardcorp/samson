from samson.math.general import fast_mul, square_and_mul
from abc import ABC, abstractmethod

class Ring(ABC):

    @abstractmethod
    def shorthand(self) -> str:
        pass

    def __str__(self):
        return self.shorthand()

    @abstractmethod
    def zero(self):
        pass

    @abstractmethod
    def one(self):
        pass

    @abstractmethod
    def random(self, size: int=None):
        pass

    def coerce(self, other: object) -> object:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            RingElement: Coerced element.
        """
        return other


    def mul_group(self) -> object:
        from samson.math.algebra.rings.multiplicative_group import MultiplicativeGroup
        return MultiplicativeGroup(self)


    __mul__ = mul_group


    def __call__(self, args):
        return self.coerce(args)


    def __truediv__(self, element):
        from samson.math.algebra.rings.quotient_ring import QuotientRing
        if element.ring != self:
            raise RuntimeError(f"'element' must be an element of the ring")

        return QuotientRing(element, self)

    def __getitem__(self, x: int):
        from samson.math.algebra.rings.polynomial_ring import PolynomialRing
        return PolynomialRing(self)


class RingElement(ABC):
    def __init__(self, ring: Ring):
        self.ring = ring


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}({str(self.val)})'

    def __str__(self):
        return self.shorthand()

    def __hash__(self) -> int:
        return hash((self.ring, self.val))

    @abstractmethod
    def __add__(self, other: object) -> object:
        pass

    def __radd__(self, other: object) -> object:
        return self.ring.coerce(other) + self

    @abstractmethod
    def __sub__(self, other: object) -> object:
        pass

    def __rsub__(self, other: object) -> object:
        return self.ring.coerce(other) - self

    __mul__ = fast_mul
    __pow__ = square_and_mul

    def __rmul__(self, other: int) -> object:
        if type(other) is int:
            return self * other

        return self.ring.coerce(other) * self

    def __bool__(self) -> bool:
        return self != self.ring.zero()

    def __eq__(self, other: object) -> bool:
        other = self.ring.coerce(other)
        return self.val == other.val and self.ring == other.ring

    def __lt__(self, other: object) -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.val < other.val

    def __gt__(self, other: object) -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.val > other.val


    def __int__(self) -> int:
        return int(self.val)
