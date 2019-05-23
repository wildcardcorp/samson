from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import mod_inv

class QuotientElement(RingElement):
    def __init__(self, val: int, ring: Ring):
        self.ring = ring
        self.val  = val % self.ring.quotient
    

    def __repr__(self):
        return f"<QuotientElement: val={self.val}, ring={self.ring}>"

    def __str__(self):
        return self.__repr__()


    def shorthand(self) -> str:
        return self.val.shorthand()


    def coerce(self, other: int) -> object:
        if type(other) is int:
            other = QuotientElement(other, self.ring)
        return other

    def __add__(self, other: object) -> object:
        other = self.coerce(other)
        return QuotientElement((self.val + other.val) % self.ring.quotient, self.ring)

    def __sub__(self, other: object) -> object:
        other = self.coerce(other)
        return QuotientElement((self.val - other.val) % self.ring.quotient, self.ring)

    def __mul__(self, other: object) -> object:
        other = self.coerce(other)
        return QuotientElement((self.val * other.val) % self.ring.quotient, self.ring)

    def __mod__(self, other: object) -> object:
        other = self.coerce(other)
        return QuotientElement((self.val % other.val) % self.ring.quotient, self.ring)

    def __truediv__(self, other: object) -> object:
        other = self.coerce(other)
        return QuotientElement((self.val * mod_inv(other.val, self.ring.quotient)) % self.ring.quotient, self.ring)

    def __floordiv__(self, other: object) -> object:
        other = self.coerce(other)
        return QuotientElement((self.val // other.val) % self.ring.quotient, self.ring)

    def __neg__(self) -> object:
        return QuotientElement((-self.val) % self.ring.quotient, self.ring)

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


class QuotientRing(Ring):
    ELEMENT = QuotientElement

    def __init__(self, quotient, ring):
        assert(quotient.ring == ring)
        self.ring     = ring
        self.quotient = quotient


    def zero(self) -> QuotientElement:
        return QuotientElement(self.ring.zero(), self)

    def one(self) -> QuotientElement:
        return QuotientElement(self.ring.one(), self)
    

    def __repr__(self):
        return f"<QuotientRing ring={self.ring}, quotient={self.quotient}>"

    def __str__(self):
        return self.__repr__()
    

    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}/{self.quotient.shorthand()}'

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.quotient == other.quotient

    def __call__(self, args):
        return self.ELEMENT(self.ring(args), self)