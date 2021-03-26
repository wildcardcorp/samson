from samson.math.algebra.curves.weierstrass_curve import EllipticCurve, WeierstrassPoint
from samson.math.factorization.general import factor
from samson.math.general import random_int_between, is_prime
from samson.core.primitives import KeyExchangeAlg, Primitive
from samson.core.metadata import SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive
import math


def find_ss_prime(a: int, b: int, min_bits: int, max_strength_diff: float=0.005):
    a_mod   = math.log(b, a)
    min_exp = math.ceil(min_bits/math.log(b**2, 2))

    p = 1
    i = min_exp-1
    e = 0

    # Add cofactor if we're not using 2, otherwise we'll never get a prime
    f = 4 if 2 not in [a, b] else 1
    while not is_prime(p) or abs(1-math.log(a**e, b**i)) > max_strength_diff:
        i += 1
        e = round(i*a_mod)
        p = f*a**e*b**i-1

    return p


def find_linearly_independent_points(E, n):
    while True:
        P, Q = [E.find_element_of_order(n, allow_order_call=True) for _ in range(2)]
        if not P.linear_relation(Q)[0]:
            return P, Q
        # w = P.weil_pairing(Q, n)
        # if w.ring.mul_group()(w).order() == n:
        #     return P, Q


def extract_prime_powers(p):
    facs = list(factor(p+1).items())

    if len(facs) == 2:
        (wa, ea), (wb, eb) = facs
    else:
        # Remove cofactor
        (_, _), (wb, eb), (wa, ea) = sorted(facs, key=lambda item: item[0])

    return wa, ea, wb, eb



@register_primitive()
class SIDH(KeyExchangeAlg):
    """
    Supersingular Isogeny Diffie-Hellman.
    """

    KEY_SIZE        = SizeSpec(size_type=SizeType.ARBITRARY, typical=[434, 503, 610, 751])
    USAGE_FREQUENCY = FrequencyType.UNUSUAL

    def __init__(self, curve: EllipticCurve, Pa: WeierstrassPoint, Qa: WeierstrassPoint, Pb: WeierstrassPoint, Qb: WeierstrassPoint, use_a: bool, n: int=None, m: int=None):
        """
        Parameters:
            curve (EllipticCurve): Starting curve.
            Pa (WeierstrassPoint): `A`'s `P` point.
            Qa (WeierstrassPoint): `A`'s `Q` point.
            Pb (WeierstrassPoint): `B`'s `P` point.
            Qb (WeierstrassPoint): `B`'s `Q` point.
            use_a          (bool): Whether to use `A` points or `B` points.
            n               (int): `P` coefficient.
            m               (int): `Q` coefficient.
        """
        Primitive.__init__(self)

        self.curve = curve

        wa, ea, wb, eb = extract_prime_powers(curve.ring.characteristic())

        if use_a:
            self.prime_power = (wa, ea)
            order = wa**ea
            P, Q  = Pa, Qa
            U, V  = Pb, Qb
        else:
            self.prime_power = (wb, eb)
            order = wb**eb
            P, Q  = Pb, Qb
            U, V  = Pa, Qa

        self.n = n or random_int_between(1, order)
        self.m = m or random_int_between(1, order)
        self.R = P*self.n + Q*self.m

        self.phi = curve.isogeny(self.R)
        self.iU  = self.phi(U)
        self.iV  = self.phi(V)


    @property
    def pub(self):
        return (self.phi.codomain, self.iU, self.iV)



    def derive_key(self, challenge: tuple) -> object:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (WeierstrassPoint): The other instance's challenge.
        
        Returns:
            object: Shared key.
        """
        Eb, iU, iV = challenge
        S   = iU*self.n + iV*self.m
        Eab = Eb.isogeny(S)

        return Eab.codomain.j_invariant()


    @staticmethod
    def generate_public_parameters(a: int=2, b: int=3, min_bits: int=160, max_strength_diff: float=0.005) -> (EllipticCurve, WeierstrassPoint, WeierstrassPoint, WeierstrassPoint, WeierstrassPoint):
        """
        Generates public parameters suitable for SIDH.

        Parameters:
            a                   (int): Prime for party `A`.
            b                   (int): Prime for party `B`.
            min_bits            (int): Minimum bit prime.
            max_strength_diff (float): Maximum strength difference between prime-power subgroups.

        Returns:
            (EllipticCurve, WeierstrassPoint, WeierstrassPoint, WeierstrassPoint, WeierstrassPoint): Formatted as (curve, Pa, Qa, Pb, Qb).
        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.symbols import Symbol
        from samson.math.algebra.fields.finite_field import FiniteField as GF

        p = find_ss_prime(a, b, min_bits, max_strength_diff=max_strength_diff)
        R = ZZ/ZZ(p)
        i = Symbol('i')
        _ = R[i]

        # Try this poly first (convention)
        red_poly = i**2+1
        if not red_poly.is_irreducible():
            red_poly = None


        F = GF(p, 2, reducing_poly=red_poly)
        E = EllipticCurve.generate_supersingular_over_ring(F)

        wa, ea, wb, eb = extract_prime_powers(p)

        Pa, Qa = find_linearly_independent_points(E, wa**ea)
        Pb, Qb = find_linearly_independent_points(E, wb**eb)

        return E, Pa, Qa, Pb, Qb
