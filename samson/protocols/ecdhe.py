from samson.math.algebra.curves.named import P256
from samson.math.algebra.curves.weierstrass_curve import WeierstrassPoint
from samson.math.general import random_int
from samson.utilities.bytes import Bytes
from samson.core.primitives import KeyExchangeAlg, Primitive
from samson.core.metadata import SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive


@register_primitive()
class ECDHE(KeyExchangeAlg):
    """
    Elliptical curve Diffie-Hellman (Ephemeral).
    """

    KEY_SIZE        = SizeSpec(size_type=SizeType.RANGE, sizes=[192, 224, 256, 384, 521])
    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, d: int=None, pub: WeierstrassPoint=None, G: WeierstrassPoint=P256.G):
        """
        Parameters:
            d              (int): Secret key.
            G (WeierstrassPoint): Generator point on an elliptical curve.
        """
        Primitive.__init__(self)
        self.d   = d or random_int(G.ring.cardinality())
        self.G   = G
        self.pub = pub

        if not pub:
            self.recompute_pub()



    def recompute_pub(self) -> WeierstrassPoint:
        """
        Gets the challenge.

        Returns:
            Point: The challenge.
        """
        self.pub = self.d * self.G


    def derive_point(self, challenge: WeierstrassPoint) -> WeierstrassPoint:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (WeierstrassPoint): The other instance's challenge.
        
        Returns:
            WeierstrassPoint: Shared key.
        """
        return self.d * challenge


    def derive_key(self, challenge: WeierstrassPoint) -> Bytes:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (WeierstrassPoint): The other instance's challenge.
        
        Returns:
            Bytes: Shared key.
        """
        shared_key = self.d * challenge
        if not shared_key:
            raise ValueError('Cannot derive bytes from point at infinity')

        return Bytes(int(shared_key.x) % self.G.curve.p).zfill((self.G.curve.p.bit_length() + 7) // 8)
