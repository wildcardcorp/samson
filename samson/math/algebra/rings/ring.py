from abc import ABC, abstractmethod

class Ring(ABC):
    ELEMENT = None

    @abstractmethod
    def zero(self):
        pass

    @abstractmethod
    def one(self):
        pass

    def __call__(self, args):
        return self.ELEMENT(args, self)
    
    def __truediv__(self, element):
        from samson.math.algebra.rings.quotient_ring import QuotientRing
        return QuotientRing(element, self)


class RingElement(ABC):
    def __init__(self, ring: Ring):
        self.ring = ring

    def coerce(self, other: object) -> object:
        return other

    @abstractmethod
    def __add__(self, other: object) -> object:
        pass

    @abstractmethod
    def __sub__(self, other: object) -> object:
        pass

    @abstractmethod
    def __mul__(self, other: object) -> object:
        pass

    def __pow__(self, other: int) -> object:
        s = 1
        g = self
        while other != 0:
            if other & 1:
                s = (s * g)
            other >>= 1
            g = (g * g)
        return s



    def __bool__(self) -> bool:
        return self != self.ring.zero()
    

    def __eq__(self, other: object) -> bool:
        other = self.coerce(other)
        return self.val == other.val and self.ring == other.ring

    def __lt__(self, other: object) -> bool:
        other = self.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.val < other.val

    def __gt__(self, other: object) -> bool:
        other = self.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.val > other.val