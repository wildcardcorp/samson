from sympy import GF
from samson.utilities.math import mod_inv
from fastecdsa.curve import P192, P224, P256, P384, P521
import math

# Convenience aliases
secp192r1 = P192
secp224r1 = P224
secp256r1 = P256
secp384r1 = P384
secp521r1 = P521


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
class MontgomeryCurve(object):
    """
    Montgomery Curve

    Basically just decouples parameters from `MontgomeryPoint`.
    """

    # # https://tools.ietf.org/html/rfc7748#section-3
    def __init__(self, p: int, A: int, a24: int, U: int, V: int):
        """
        Parameters:
            p   (int): Prime number defining the underlying field.
            A   (int): An element in the finite field GF(p), not equal to -2 or 2.
            a24 (int): Constant for curve multiplication.
            U   (int): The u-coordinate of the elliptic curve point P on a Montgomery curve.
            V   (int): The v-coordinate of the elliptic curve point P on a Montgomery curve.
        """
        self.p = p
        self.A = A
        self.a24 = a24
        self.U = U
        self.V = V


    def __repr__(self):
        return f"<MontgomeryCurve: p={self.p}, A={self.A}, U={self.U}, V={self.V}>"

    def __str__(self):
        return self.__repr__()


    def __eq__(self, other) -> bool:
        return self.p == other.p and self.A == other.A and self.U == other.U and self.V == other.V




class MontgomeryPoint(object):
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

    def __str__(self):
        return self.__repr__()



    def __eq__(self, other) -> bool:
        return self.x == other.x and self.curve == other.curve


    # https://tools.ietf.org/html/rfc7748#section-5
    def __mul__(self, other: int) -> int:
        if type(other) != int:
            raise NotImplementedError("MontgomeryPoint multiplication is currently only implemented for scalars.")

        A = self.curve.A
        gf_p = GF(self.curve.p)

        x_1 = gf_p(other)
        x_2 = gf_p(1)
        z_2 = gf_p(0)
        x_3 = gf_p(other)
        z_3 = gf_p(1)
        swap = 0

        for t in range(self.x.bit_length()-1, -1, -1):
            k_t = (self.x >> t) & 1
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


    def __rmul__(self, other):
        return self.__mul__(other)




class Curve25519(MontgomeryCurve):
    def __init__(self):
        super().__init__(p=2**255 - 19, A=486662, a24=121665, U=9, V=1478161944758954479102059356840998688726460613461647528896488183775558623740)


    def clamp_to_curve(self, x: int) -> MontgomeryPoint:
        """
        Coerces `x` to a valid x-coordinate on Curve25519.

        Parameters:
            x (int): `x` value to coerce.

        Returns:
            MontgomeryPoint: Valid MontgomeryPoint.
        """
        x &= ~7
        x &= ~(128 << 8 * 31)
        x |= 64 << 8 * 31
        return MontgomeryPoint(x, self)



class Curve448(MontgomeryCurve):
    def __init__(self):
        super().__init__(p=2**448 - 2**224 - 1, A=156326, a24=39081, U=5, V=355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362)


    def clamp_to_curve(self, x: int) -> MontgomeryPoint:
        """
        Coerces `x` to a valid x-coordinate on Curve448.

        Parameters:
            x (int): `x` value to coerce.

        Returns:
            MontgomeryPoint: Valid MontgomeryPoint.
        """
        x &= ~3
        x |= 128 << 8 * 55
        return MontgomeryPoint(x, self)



# https://ed25519.cr.yp.to/python/ed25519.py
# https://tools.ietf.org/html/rfc8032
class TwistedEdwardsCurve(object):
    """
    Twisted Edwards Curve

    Provides general curve operations and parameter decoupling.
    """

    # https://tools.ietf.org/html/rfc8032#section-5
    # https://tools.ietf.org/html/rfc8032#section-3
    def __init__(self, a: int, c: int, n: int, b: int, magic: bytes, q: int, l: int, d: int, B: (int, int)):
        """
        Parameters:
            a        (int): Twist parameter. a=1 is untwisted, the special case.
            c        (int): Base 2 logarithm of cofactor
            n        (int): Defines the number of bits in EdDSA scalars.
            b        (int): Number of bits the curve can encode.
            magic  (bytes): The magic byte-string (if any) of the curve.
            q        (int): Modulus.
            l        (int): Order of the curve.
            d        (int): A non-zero element in the finite field GF(p), not equal to 1, in the case of an Edwards curve, or not equal to -1, in the case of a twisted Edwards curve
            B ((int, int)): Base point.
        """
        self.a = a
        self.c = c
        self.n = n
        self.b = b
        self.magic = magic
        self.q = q
        self.l = l
        self.d = d
        self.I = pow(2, (q-1) // 4, q)
        self.B = TwistedEdwardsPoint(*B, self)


    def __repr__(self):
        return f"<TwistedEdwardsCurve: b={self.b}, q={self.q}, l={self.l}>"

    def __str__(self):
        return self.__repr__()



    def __eq__(self, other) -> bool:
        return self.b == other.b and self.q == other.q and self.l == other.l and self.d == other.d



    def is_on_curve(self, P: (int, int)) -> bool:
        """
        Determines if the point `P` is on the curve.

        Parameters:
            P (int, int): The point formatted as (x, y).

        Returns:
            bool: Whether or not the point is on the curve.
        """
        x, y = P
        return (self.a * x*x + y*y - 1 - self.d * x*x*y*y) % self.q == 0



    def recover_point_from_y(self, y: int):
        """
        Recovers the full TwistedEdwardsPoint from the y-coordinate.

        Parameters:
            y (int): y-coordinate of a valid TwistedEdwardsPoint.
        
        Returns:
            TwistedEdwardsPoint: Full TwistedEdwardsPoint.

        """
        xx = (y*y-1) * mod_inv(self.d*y*y-self.a, self.q)
        if self.q % 8 == 5:
            x = pow(xx, (self.q+3)//8, self.q)

            if (x*x - xx) % self.q != 0:
                x = (x*self.I) % self.q

            if x % 2 != 0:
                x = self.q-x

        elif self.q % 4 == 3:
            x = pow(xx, (self.q+1)//4, self.q)
        else:
            raise Exception("Unsupported prime `q`.")

        return TwistedEdwardsPoint(x % self.q, y % self.q, self)




class TwistedEdwardsPoint(object):
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
        self.x = x % curve.q
        self.y = y % curve.q

        if validate and not curve.is_on_curve((x, y)):
            raise ValueError(f"({x}, {y}) is not on {curve}")



    def __repr__(self):
        return f"<TwistedEdwardsPoint: x={self.x}, y={self.y}, curve={self.curve}>"

    def __str__(self):
        return self.__repr__()



    def __eq__(self, other) -> bool:
        return self.x == other.x and self.y == other.y and self.curve == other.curve


    def __add__(self, other):
        if type(other) != TwistedEdwardsPoint:
            raise TypeError("TwistedEdwardsPoint addition only defined between points.")

        assert self.curve == other.curve

        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        x3 = (x1*y2+x2*y1) * mod_inv(1+self.curve.d * x1*x2*y1*y2, self.curve.q)
        y3 = (y1*y2 - self.curve.a*x1*x2) * mod_inv(1-self.curve.d * x1*x2*y1*y2, self.curve.q)

        return TwistedEdwardsPoint(x3, y3, self.curve)


    def __mul__(self, scalar: int):
        if type(scalar) != int:
            raise NotImplementedError("TwistedEdwardsPoint multiplication is currently only implemented for scalars.")

        Q = TwistedEdwardsPoint(0, 1, self.curve)
        iters = math.ceil(math.log(scalar, 2))

        for i in range(iters-1, -1, -1):
            Q = Q + Q

            if (scalar >> i) & 1:
                Q = Q + self

        return Q


    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)




EdwardsCurve25519 = TwistedEdwardsCurve(a=-1, c=3, n=254, b=256, magic=b'', q=2**255 - 19, l=2**252 + 27742317777372353535851937790883648493, d=-121665 * pow(121666, 2**255 - 19 -2, 2**255 - 19), B=(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960))
EdwardsCurve448   = TwistedEdwardsCurve(a=1, c=2, n=447, b=456, magic=b'SigEd448\x00\x00', q=2**448 - 2**224 - 1, l=2**446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d, d=-39081, B=(224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710, 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660))
