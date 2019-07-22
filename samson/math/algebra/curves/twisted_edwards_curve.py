from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import random_int
from samson.utilities.bytes import Bytes

def bit(h,i):
  return (h[i//8] >> (i%8)) & 1


# https://ed25519.cr.yp.to/python/ed25519.py
# https://tools.ietf.org/html/rfc8032
class TwistedEdwardsCurve(Ring):
    """
    Twisted Edwards Curve

    Provides general curve operations and parameter decoupling.
    """

    # https://tools.ietf.org/html/rfc8032#section-5
    # https://tools.ietf.org/html/rfc8032#section-3
    def __init__(self, oid: str, a: int, c: int, n: int, b: int, magic: bytes, l: int, d: int, B: (int, int), ring: Ring=None):
        """
        Parameters:
            oid      (str): Curve OID.
            a        (int): Twist parameter. a=1 is untwisted, the special case.
            c        (int): Base 2 logarithm of cofactor
            n        (int): Defines the number of bits in EdDSA scalars.
            b        (int): Number of bits the curve can encode.
            magic  (bytes): The magic byte-string (if any) of the curve.
            l        (int): Order of the curve.
            d        (int): A non-zero element in the finite field GF(q), not equal to 1, in the case of an Edwards curve, or not equal to -1, in the case of a twisted Edwards curve
            B ((int, int)): Base point.
        """
        self.oid = oid
        self.a = a
        self.c = c
        self.n = n
        self.b = b
        self.magic = magic
        self.l = l
        self.d = d
        self.ring = ring or d.ring
        self.B = TwistedEdwardsPoint(*B, self)
        self.I = ring(2) ** ((self.q-1) // 4)


    def __repr__(self):
        return f"<TwistedEdwardsCurve: b={self.b}, q={self.q}, l={self.l}>"


    def zero(self) -> object:
        """
        Returns:
            TwistedEdwardsCurve: '0' element of the algebra.
        """
        return TwistedEdwardsPoint(0, 1, self)


    def one(self) -> object:
        """
        Returns:
            TwistedEdwardsCurve: '1' element of the algebra.
        """
        return self.B


    def random(self, size: int=None) -> object:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            TwistedEdwardsCurve: Random element of the algebra.
        """
        return self.B * random_int(size or self.q)


    @property
    def q(self):
        return int(self.ring.quotient)


    def element_at(self, x: int) -> object:
        """
        Returns the `x`-th element w.r.t to the generator.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           TwistedEdwardsPoint: The `x`-th point.
        """
        return self.B*x


    def shorthand(self) -> str:
        return f'TwistedEdwardsCurve{{a={self.a}, l={self.l}, q={self.q}, B={(str(self.B.x), str(self.B.y))}}}'


    def __eq__(self, other) -> bool:
        return self.b == other.b and self.q == other.q and self.l == other.l and self.d == other.d

    def __hash__(self) -> int:
        return Bytes(self.oid.encode()).int()



    def clamp_to_curve(self, x: int, swap_bit_order: bool=True) -> int:
        """
        Coerces `x` to a valid x-coordinate on the curve.

        Parameters:
            x               (int): `x` value to coerce.
            swap_bit_order (bool): Whether or not to swap the bit order before processing.

        Returns:
            int: Valid x-coordinate.
        """
        from samson.utilities.manipulation import get_blocks

        as_bits = bin(x)[2:].zfill(self.b)
        if swap_bit_order:
            as_bits = ''.join([block[::-1] for block in get_blocks(as_bits, 8)])

        return 2**(self.n) | sum(2**i * int((as_bits)[i]) for i in range(self.c, self.n))



    def is_on_curve(self, P: (int, int)) -> bool:
        """
        Determines if the point `P` is on the curve.

        Parameters:
            P (int, int): The point formatted as (x, y).

        Returns:
            bool: Whether or not the point is on the curve.
        """
        x, y = P
        return self.a * x*x + y*y - self.ring.one() - self.d * x*x*y*y == self.ring.zero()



    def recover_point_from_y(self, y: int) -> object:
        """
        Recovers the full TwistedEdwardsPoint from the y-coordinate.

        Parameters:
            y (int): y-coordinate of a valid TwistedEdwardsPoint.
        
        Returns:
            TwistedEdwardsPoint: Full TwistedEdwardsPoint.

        """
        y  = self.ring.coerce(y)
        xx = (y*y-1) * ~(self.d*y*y-self.a)

        if self.q % 8 == 5:
            x = xx ** ((self.q+3)//8)

            if (x*x - xx) != self.ring.zero():
                x = (x*self.I)

            if x % 2 != self.ring.zero():
                x = -x

        elif self.q % 4 == 3:
            x = xx**((self.q+1)//4)
        else:
            raise Exception("Unsupported prime `q`.")

        return TwistedEdwardsPoint(x, y, self)




class TwistedEdwardsPoint(RingElement):
    """
    Point on a Twisted Edwards Curve

    Provides scalar multiplication and point addition.
    """

    def __init__(self, x: int, y: int, curve: TwistedEdwardsCurve, validate: bool=True):
        """
        Parameters:
            x                     (int): x-coordinate.
            y                     (int): y-coordinate.
            curve (TwistedEdwardsCurve): Underlying curve.
            validate             (bool): Whether or not to validate the point against the curve.
        """
        self.curve = curve
        self.x = self.curve.ring.coerce(x)
        self.y = self.curve.ring.coerce(y)

        if validate and not curve.is_on_curve((self.x, self.y)):
            raise ValueError(f"({x}, {y}) is not on {curve}")



    def __repr__(self):
        return f"<TwistedEdwardsPoint: x={self.x}, y={self.y}, curve={self.curve}>"


    @property
    def ring(self):
        return self.curve


    def __eq__(self, other) -> bool:
        return self.x == other.x and self.y == other.y and self.curve == other.curve


    def __neg__(self) -> object:
        return TwistedEdwardsPoint(self.x, -self.y, self.curve)


    def __add__(self, other: object) -> object:
        if type(other) != TwistedEdwardsPoint:
            raise TypeError(f"TwistedEdwardsPoint addition only defined between points. Type {type(other)} given.")

        assert self.curve == other.curve
        ring = self.curve.ring

        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        x3 = (x1*y2+x2*y1) * ~(ring.one()+self.curve.d * x1*x2*y1*y2)
        y3 = (y1*y2 - self.curve.a*x1*x2) * ~(ring.one()-self.curve.d * x1*x2*y1*y2)

        return TwistedEdwardsPoint(x3, y3, self.curve)


    def __sub__(self, other: object) -> object:
        if type(other) != TwistedEdwardsPoint:
            raise TypeError("TwistedEdwardsPoint subtraction only defined between points.")

        assert self.curve == other.curve
        return self + -other
