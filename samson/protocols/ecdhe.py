from samson.math.algebra.curves.named import P256
from samson.math.algebra.curves.weierstrass_curve import WeierstrassPoint
from samson.math.general import random_int
from samson.utilities.bytes import Bytes

class ECDHE(object):
    """
    Elliptical curve Diffie-Hellman (Ephemeral).
    """

    def __init__(self, d: int=None, pub: WeierstrassPoint=None, G: WeierstrassPoint=P256.G):
        """
        Parameters:
            d              (int): Secret key.
            G (WeierstrassPoint): Generator point on an elliptical curve.
        """
        self.d   = d or random_int(G.ring.cardinality())
        self.G   = G
        self.pub = pub

        if not pub:
            self.recompute_pub()



    def __repr__(self):
        return f"<ECDHE: d={self.d}, pub={self.pub}, G={self.G}>"

    def __str__(self):
        return self.__repr__()


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
        return Bytes(int((self.d * challenge).x) % self.G.curve.p).zfill((self.G.curve.p.bit_length() + 7) // 8)
