from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.factorization.general import factor
from samson.math.map import Map
from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import CoercionException

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

    # https://tools.ietf.org/html/rfc7748#section-3
    def __init__(self, A: RingElement, U: RingElement=None, V: RingElement=None, a24: int=None, oid: str=None, ring: Ring=None, order: int=None, B: RingElement=None):
        """
        Parameters:
            A   (int): An element in the finite field GF(p), not equal to -2 or 2.
            U   (int): The u-coordinate of the elliptic curve point P on a Montgomery curve.
            V   (int): The v-coordinate of the elliptic curve point P on a Montgomery curve.
            a24 (int): Constant for curve multiplication.
        """
        self.A    = A
        self.a24  = a24 or (A-2) // 4
        self.U    = U
        self.V    = V
        self.oid  = oid
        self.ring = ring or A.ring
        self.B    = B or self.ring.one

        self.zero = self(0)
        self._order = order



    def __reprdir__(self):
        return ['p', 'A', 'B', 'U', 'V']


    def shorthand(self) -> str:
        return f'MontgomeryCurve{{A={self.A}, B={self.B}, U={self.U}, V={self.V}}}'



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
                return self(self.ring.random(size))
            except CoercionException:
                pass


    @property
    def p(self) -> int:
        return self.ring.characteristic()


    @property
    def G(self) -> 'MontgomeryPoint':
        if not self.U:
            self.U = self.find_gen().x
        return self(self.U)


    def order(self) -> int:
        if not self._order:
            self._order = self.to_weierstrass_form()[0].order() // 2
        return self._order


    def element_at(self, x: int) -> 'MontgomeryPoint':
        """
        Returns the `x`-th element w.r.t to the generator.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           MontgomeryPoint: The `x`-th point.
        """
        return self.G*x


    def coerce(self, x: 'RingElement', verify: bool=True) -> 'MontgomeryPoint':
        if type(x) is MontgomeryPoint:
            if x.curve == self:
                return x
            else:
                return self(x.x)

        if verify:
            v = (x**3 + self.A*x**2 + x)/self.B
            if not v.is_square():
                raise CoercionException(f"{x} is not on curve {self}")

        return MontgomeryPoint(self.ring(x), self)



    def __eq__(self, other) -> bool:
        return type(self) == type(other) and self.p == other.p and self.A == other.A and self.U == other.U and self.V == other.V

    def __hash__(self) -> int:
        return Bytes(self.oid.encode()).int() if self.oid else hash((self.A, self.B))


    def to_weierstrass_form(self) -> 'WeierstrassCurve':
        """
        References:
            https://en.wikipedia.org/wiki/Montgomery_curve#Equivalence_with_Weierstrass_curves
        """
        from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve
        A = self.A
        B = self.B

        if self.U is not None and self.V is not None:
            x = (self.U/B) + (A/(3*B))
            y = self.V/B
            G = (x, y)
        else:
            G = None

        a = (3-A**2) / (3*B**2)
        b = (2*A**3 - 9*A) / (27*B**3)

        curve     = WeierstrassCurve(a=a, b=b, base_tuple=G, cardinality=self.order()*2 if self._order else None)
        point_map = Map(self, curve, lambda point: curve((point.x/B) + (A/(3*B))))

        return curve, point_map



    def find_gen(self):
        E, _ = self.to_weierstrass_form()
        G    = E.find_gen()

        s     = self.B
        alpha = self.A/(3*s)
        return self(s*(G.x-alpha))


    def __two_isogeny(self, P):
        x2   = P.x
        A, B = 2*(1-2*x2), self.B*x2

        curve = MontgomeryCurve(A=A, B=B)


        def map_func(Q):
            x, y = Q.x, Q.Y
            xp2x = x**2*x2
            xp2  = x-x2

            xP = (xp2x - x)/(xp2)
            #yP = y*(xp2x-2*x*x2**2+x2)/xp2**2
            return curve(xP)
        
        return Map(domain=self, codomain=curve, map_func=map_func)


    def isogeny(self, P: 'MontgomeryPoint') -> 'EllipticCurveIsogeny':
        if P.ring != self:
            raise ValueError(f'{P} is not on {self}')

        n      = P.order()
        n_facs = factor(n)
        phi    = None

        for p, e in n_facs.items():
            Q = P*(n // p**e)

            for i in range(1, e+1):
                old_phi = phi
                phi = self.__two_isogeny(Q*(p**(e-i)))
                #phi = EllipticCurveIsogeny(E, Q*(p**(e-i)), pre_isomorphism=phi)
                Q   = phi(Q)
                phi.pre_isomorphism = old_phi

            P = phi(P)

        return phi



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
        self.x = curve.ring(x)
        self.curve = curve
        self.order_cache  = None
    
    

    def __hash__(self):
        return hash((self.curve, self.x))


    @property
    def ring(self):
        return self.curve


    def tinyhand(self):
        return str(self.x) if type(self.x) is int else self.x.val.tinyhand()


    def __eq__(self, other: 'MontgomeryPoint') -> bool:
        return self.x == other.x and self.curve == other.curve


    def __add__(self, P2: 'MontgomeryPoint') -> 'MontgomeryPoint':
        if P2 == self:
            return self*2
        raise NotImplementedError()

    def __sub__(self, other: 'MontgomeryPoint') -> 'MontgomeryPoint':
        raise NotImplementedError()


    def cache_mul(self, size: int) -> 'BitVectorCache':
        """
        Montgomery points can't use the BitVectorCache as they does support element addition.
        """
        return self


    # https://tools.ietf.org/html/rfc7748#section-5
    def __mul__(self, other):
        u = self.x
        k = other % self.curve.order()
        u2, w2 = (1, 0)
        u3, w3 = (u, 1)
        p = u.ring.characteristic()
        A = self.curve.A

        for i in reversed(range(p.bit_length())):
            b = 1 & (k >> i)
            u2, u3 = cswap(b, u2, u3)
            w2, w3 = cswap(b, w2, w3)
            u3, w3 = ((u2*u3 - w2*w3)**2,
                        u * (u2*w3 - w2*u3)**2)
            u2, w2 = ((u2**2 - w2**2)**2,
                        4*u2*w2 * (u2**2 + A*u2*w2 + w2**2))
            u2, u3 = cswap(b ,u2, u3)
            w2, w3 = cswap(b, w2, w3)

        return MontgomeryPoint(u2 * w2**(p-2), self.curve)



    def to_weierstrass_coordinate(self) -> 'WeierstrassPoint':
        A = self.curve.A
        B = self.curve.B
        return (self.x/B) + (A/(3*B))




class Curve25519Crv(MontgomeryCurve):
    def __init__(self):
        ring = ZZ/ZZ(2**255 - 19)
        super().__init__(A=ring(486662), a24=121665, U=ring(9), V=ring(14781619447589544791020593568409986887264606134616475288964881837755586237401), oid='1.3.101.110', order=(2**252 + 0x14def9dea2f79cd65812631a5cf5d3ed)*8)


    def clamp_to_curve(self, x: int) -> int:
        """
        Coerces `x` to a valid x-coordinate on Curve25519.

        Parameters:
            x (int): `x` value to coerce.

        Returns:
            int: Valid MontgomeryPoint.
        """
        x  = int(x)
        x &= ~7
        x &= ~(128 << 8 * 31)
        x |= 64 << 8 * 31
        return x



class Curve448Crv(MontgomeryCurve):
    def __init__(self):
        ring = ZZ/ZZ(2**448 - 2**224 - 1)
        super().__init__(A=ring(156326), a24=39081, U=ring(5), V=ring(355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362), oid='1.3.101.111', order=(2**446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d)*4)


    def clamp_to_curve(self, x: int) -> int:
        """
        Coerces `x` to a valid x-coordinate on Curve448.

        Parameters:
            x (int): `x` value to coerce.

        Returns:
            int: Valid MontgomeryPoint.
        """
        x  = int(x)
        x &= ~3
        x |= 128 << 8 * 55
        return x
