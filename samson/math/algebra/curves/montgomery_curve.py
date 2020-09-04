from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import random_int_between
from samson.utilities.bytes import Bytes

# https://tools.ietf.org/html/rfc7748
def cswap(swap: int, x_2: int, x_3: int) -> (int, int):
    """
    Conditional constant-time swap.

    Parameters:
        swap (int): 0 or 1. 1 means swap.
        x_2  (int): First int.
        x_3  (int): Second int.

    Returns:
        (int, int): Formatted as (x_2, x_3)
    """
    dummy = swap * (x_2 - x_3)
    x_2 = x_2 - dummy
    x_3 = x_3 + dummy
    return (x_2, x_3)



# https://tools.ietf.org/html/rfc7748#section-4.1
class MontgomeryCurve(Ring):
    """
    Montgomery Curve

    Basically just decouples parameters from `MontgomeryPoint`.
    """

    # # https://tools.ietf.org/html/rfc7748#section-3
    def __init__(self, A: RingElement, a24: int, U: RingElement, V: RingElement, oid: str=None, ring: Ring=None):
        """
        Parameters:
            A   (int): An element in the finite field GF(p), not equal to -2 or 2.
            a24 (int): Constant for curve multiplication.
            U   (int): The u-coordinate of the elliptic curve point P on a Montgomery curve.
            V   (int): The v-coordinate of the elliptic curve point P on a Montgomery curve.
        """
        self.A   = A
        self.a24 = a24
        self.U   = U
        self.V   = V
        self.oid = oid
        self.ring = ring or A.ring

        self.zero = MontgomeryPoint(0, self)
        self.one  = self.G


    def __repr__(self):
        return f"<MontgomeryCurve: p={self.p}, A={self.A}, U={self.U}, V={self.V}>"


    def shorthand(self) -> str:
        return f'MontgomeryCurve{{A={self.A}, U={self.U}, V={self.V}}}'



    def random(self, size: int=None) -> 'MontgomeryPoint':
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            MontgomeryPoint: Random element of the algebra.
        """
        while True:
            try:
                return self.clamp_to_curve(random_int_between(1, size or self.p))
            except AssertionError:
                pass


    @property
    def p(self) -> int:
        return int(self.ring.quotient)


    @property
    def G(self) -> 'MontgomeryPoint':
        return MontgomeryPoint(self.U, self)


    def element_at(self, x: int) -> 'MontgomeryPoint':
        """
        Returns the `x`-th element w.r.t to the generator.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           MontgomeryPoint: The `x`-th point.
        """
        return self.G*x

    def __eq__(self, other) -> bool:
        return self.p == other.p and self.A == other.A and self.U == other.U and self.V == other.V

    def __hash__(self) -> int:
        return Bytes(self.oid.encode()).int()



class MontgomeryPoint(RingElement):
    """
    Point on a Montgomery Curve

    Provides scalar multiplication.
    """

    def __init__(self, x: int, curve: MontgomeryCurve):
        """
        Parameters:
            x                 (int): x-coordinate.
            curve (MontgomeryCurve): The underlying curve.
        """
        self.curve = curve
        self.x = x


    def __repr__(self):
        return f"<MontgomeryPoint: x={self.x}, curve={self.curve}>"


    @property
    def ring(self):
        return self.curve


    def tinyhand(self):
        return str(self.x) if type(self.x) is int else self.x.val.tinyhand()


    def __eq__(self, other: 'MontgomeryPoint') -> bool:
        return self.x == other.x and self.curve == other.curve


    def __add__(self, P2: 'MontgomeryPoint') -> 'MontgomeryPoint':
        raise NotImplementedError()

    def __sub__(self, other: 'MontgomeryPoint') -> 'MontgomeryPoint':
        raise NotImplementedError()

    # https://tools.ietf.org/html/rfc7748#section-5
    def __mul__(self, other: int) -> int:
        A   = self.curve.A
        x_1 = self.curve.ring.coerce(other)
        x_2 = self.curve.ring(1)
        z_2 = self.curve.ring(0)
        x_3 = self.curve.ring.coerce(other)
        z_3 = self.curve.ring(1)
        swap = 0

        self_x = int(self.x)

        for t in range(self_x.bit_length()-1, -1, -1):
            k_t = (self_x >> t) & 1
            swap ^= k_t

            # Conditional swap
            x_2, x_3 = cswap(swap, x_2, x_3)
            z_2, z_3 = cswap(swap, z_2, z_3)
            swap = k_t

            A = x_2 + z_2
            AA = A**2
            B = x_2 - z_2
            BB = B**2
            E = AA - BB
            C = x_3 + z_3
            D = x_3 - z_3
            DA = D * A
            CB = C * B
            x_3 = (DA + CB)**2
            z_3 = x_1 * (DA - CB)**2
            x_2 = AA * BB
            z_2 = E * (AA + self.curve.a24 * E)

        # Conditional swap
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        return int(x_2 * (z_2**(self.curve.p - 2))) % self.curve.p



class Curve25519Crv(MontgomeryCurve):
    def __init__(self):
        ring = ZZ/ZZ(2**255 - 19)
        super().__init__(A=ring(486662), a24=121665, U=ring(9), V=ring(14781619447589544791020593568409986887264606134616475288964881837755586237401), oid='1.3.101.110')


    def clamp_to_curve(self, x: int) -> MontgomeryPoint:
        """
        Coerces `x` to a valid x-coordinate on Curve25519.

        Parameters:
            x (int): `x` value to coerce.

        Returns:
            MontgomeryPoint: Valid MontgomeryPoint.
        """
        x  = int(x)
        x &= ~7
        x &= ~(128 << 8 * 31)
        x |= 64 << 8 * 31
        return MontgomeryPoint(x, self)



class Curve448Crv(MontgomeryCurve):
    def __init__(self):
        ring = ZZ/ZZ(2**448 - 2**224 - 1)
        super().__init__(A=ring(156326), a24=39081, U=ring(5), V=ring(355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362), oid='1.3.101.111')


    def clamp_to_curve(self, x: int) -> MontgomeryPoint:
        """
        Coerces `x` to a valid x-coordinate on Curve448.

        Parameters:
            x (int): `x` value to coerce.

        Returns:
            MontgomeryPoint: Valid MontgomeryPoint.
        """
        x  = int(x)
        x &= ~3
        x |= 128 << 8 * 55
        return MontgomeryPoint(x, self)
