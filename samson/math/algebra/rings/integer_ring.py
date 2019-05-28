from samson.math.algebra.rings.ring import Ring, RingElement

class IntegerElement(RingElement):
    def __init__(self, val: int, ring: Ring):
        self.ring = ring
        self.val  = val


    def __repr__(self):
        return f"<IntegerElement: val={self.val}, ring={self.ring}>"


    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegerElement(self.val + other.val, self.ring)

    def __radd__(self, other: object) -> object:
        return self.ring.coerce(other) + self

    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegerElement(self.val - other.val, self.ring)

    def __rsub__(self, other: object) -> object:
        return self.ring.coerce(other) - self

    def __mul__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegerElement(self.val * other.val, self.ring)

    def __mod__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegerElement(self.val % other.val, self.ring)

    def __rmod__(self, other: object) -> object:
        return self.ring.coerce(other) % self

    def __floordiv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegerElement(self.val // other.val, self.ring)

    def __neg__(self) -> object:
        return IntegerElement(-self.val, self.ring)



class IntegerRing(Ring):
    ELEMENT = IntegerElement

    @property
    def characteristic(self):
        return 0

    def zero(self) -> IntegerElement:
        return IntegerElement(0, self)

    def one(self) -> IntegerElement:
        return IntegerElement(1, self)


    def __repr__(self):
        return f"<IntegerRing>"

    def shorthand(self) -> str:
        return 'ZZ'


    def coerce(self, other: int) -> object:
        if type(other) is int:
            other = IntegerElement(other, self)
        return other


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other)


ZZ = IntegerRing()
