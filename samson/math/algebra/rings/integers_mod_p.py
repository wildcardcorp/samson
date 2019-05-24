from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import mod_inv

class IntegersModPElement(RingElement):
    def __init__(self, val: int, ring: Ring):
        self.ring = ring
        self.val  = val % ring.p


    def __repr__(self):
        return f"<IntegersModPElement: val={self.val}, ring={self.ring}>"

    def __str__(self):
        return self.__repr__()
    

    def shorthand(self) -> str:
        return self.ring.shorthand() + f'({self.val})'


    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegersModPElement((self.val + other.val) % self.ring.p, self.ring)

    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegersModPElement((self.val - other.val) % self.ring.p, self.ring)

    def __mul__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegersModPElement((self.val * other.val) % self.ring.p, self.ring)

    def __mod__(self, other: object) -> object:
        return IntegersModPElement((self.val % other) % self.ring.p, self.ring)
    
    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return IntegersModPElement((self.val * mod_inv(other.val, self.ring.p)) % self.ring.p, self.ring)

    def __neg__(self) -> object:
        return IntegersModPElement(-self.val % self.ring.p, self.ring)

    def __invert__(self) -> object:
        return IntegersModPElement(mod_inv(self.val, self.ring.p), self.ring)




class IntegersModP(Ring):
    ELEMENT = IntegersModPElement

    def __init__(self, p: int):
        self.p = p

    def __repr__(self):
        return f"<IntegersModP: p={self.p}>"

    def __str__(self):
        return self.__repr__()


    def zero(self) -> IntegersModPElement:
        return IntegersModPElement(0, self)

    def one(self) -> IntegersModPElement:
        return IntegersModPElement(1, self)
    

    def shorthand(self) -> str:
        return f'Z/Z{self.p}'


    def coerce(self, other: int) -> object:
        if type(other) is int:
            other = IntegersModPElement(self, other)
        return other


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.p == other.p