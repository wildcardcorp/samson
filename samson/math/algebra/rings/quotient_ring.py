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
        return QuotientElement(mod_inv(self.val, self.ring.quotient), self.ring)

    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self * ~other

    def __floordiv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return QuotientElement((self.val // other.val) % self.ring.quotient, self.ring)

    def __neg__(self) -> object:
        return QuotientElement((-self.val) % self.ring.quotient, self.ring)


class QuotientRing(Ring):
    ELEMENT = QuotientElement

    def __init__(self, quotient, ring):
        assert(quotient.ring == ring)
        self.ring     = ring
        self.quotient = quotient


    def __repr__(self):
        return f"<QuotientRing ring={self.ring}, quotient={self.quotient}>"

    def __str__(self):
        return self.__repr__()


    @property
    def characteristic(self):
        return self.quotient.ring.characteristic


    def zero(self) -> QuotientElement:
        return QuotientElement(self.ring.zero(), self)

    def one(self) -> QuotientElement:
        return QuotientElement(self.ring.one(), self)
    

    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}/{self.quotient.shorthand()}'


    def coerce(self, other: int) -> object:
        if type(other) is int:
            other = QuotientElement(other, self)
        return other


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.quotient == other.quotient

    def __call__(self, args):
        return self.ELEMENT(self.ring(args), self)