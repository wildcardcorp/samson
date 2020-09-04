from samson.math.algebra.curves.montgomery_curve import MontgomeryCurve
from samson.math.algebra.curves.named import Curve25519
from samson.math.general import random_int_between
from samson.utilities.bytes import Bytes
from samson.core.primitives import KeyExchangeAlg, Primitive
from samson.core.metadata import SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive

@register_primitive()
class DH25519(KeyExchangeAlg):
    """
    Elliptical curve Diffie-Hellman using Montgomery curves.
    """

    KEY_SIZE        = SizeSpec(size_type=SizeType.ARBITRARY, typical=[255, 448])
    USAGE_FREQUENCY = FrequencyType.OFTEN

    def __init__(self, d: int=None, pub: int=None, base: int=None, curve: MontgomeryCurve=Curve25519):
        """
        Parameters:
            d                 (int): Secret key that will be clamped to the curve.
            base              (int): Base multiplier used in generating the challenge.
            curve (MontgomeryCurve): The curve used.
        """
        Primitive.__init__(self)
        self.d     = Bytes.wrap(d or random_int_between(1, curve.ring.order)).int()
        self.curve = curve
        self.key   = curve.clamp_to_curve(self.d)
        self.base  = base or curve.U

        self.pub   = pub

        if not pub:
            self.recompute_public()



    def recompute_public(self) -> int:
        """
        Gets the challenge.

        Returns:
            int: The integer challenge representing an `x` value on the curve.
        """
        self.pub = self.key * self.base



    def get_pub_bytes(self) -> Bytes:
        return Bytes(self.pub, 'little')



    def derive_key(self, challenge: int) -> Bytes:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (int): The other instance's challenge.
        
        Returns:
            int: Shared key.
        """
        return Bytes(self.key * challenge).zfill((self.curve.p.bit_length() + 7) // 8)
