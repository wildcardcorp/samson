from samson.math.algebra.curves.named import P256
from samson.math.algebra.curves.weierstrass_curve import EllipticCurve, WeierstrassPoint
from samson.math.factorization.general import factor
from samson.math.general import random_int_between
from samson.utilities.bytes import Bytes
from samson.core.primitives import KeyExchangeAlg, Primitive
from samson.core.metadata import SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive


@register_primitive()
class SIDH(KeyExchangeAlg):
    """
    Supersingular Isogeny Diffie-Hellman (Ephemeral).
    """

    # TODO: change these
    KEY_SIZE        = SizeSpec(size_type=SizeType.RANGE, sizes=[192, 224, 256, 384, 521])
    USAGE_FREQUENCY = FrequencyType.NEGLIGIBLE

    def __init__(self, curve: EllipticCurve, Pa: WeierstrassPoint, Qa: WeierstrassPoint, Pb: WeierstrassPoint, Qb: WeierstrassPoint, use_a: bool, n: int=None, m: int=None):
        """
        Parameters:
            d              (int): Secret key.
            G (WeierstrassPoint): Generator point on an elliptical curve.
        """
        Primitive.__init__(self)

        self.curve = curve

        facs = factor(curve.ring.characteristic() + 1)
        (wa, ea), (wb, eb) = facs.items()

        if use_a:
            order = wa**ea
            P, Q  = Pa, Qa
            U, V  = Pb, Qb
        else:
            order = wb**eb
            P, Q  = Pb, Qb
            U, V  = Pa, Qa

        self.n = random_int_between(1, order)
        self.m = random_int_between(1, order)
        self.R = P*self.n + Q*self.m

        self.phi = curve.isogeny(self.R)
        self.iU  = self.phi(U)
        self.iV  = self.phi(V)


    @property
    def pub(self):
        return (self.phi.codomain(), self.iU, self.iV)



    def derive_key(self, challenge: tuple) -> Bytes:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (WeierstrassPoint): The other instance's challenge.
        
        Returns:
            Bytes: Shared key.
        """
        Eb, iU, iV = challenge
        S   = iU*self.n + iV*self.m
        Eab = Eb.isogeny(S)

        return Eab.codomain().j_invariant()
