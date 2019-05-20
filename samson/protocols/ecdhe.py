from fastecdsa.curve import P256
from fastecdsa.point import Point
from samson.utilities.bytes import Bytes

class ECDHE(object):
    """
    Elliptical curve Diffie-Hellman (Ephemeral).
    """

    def __init__(self, d: int=None, pub: Point=None, G: Point=P256.G):
        """
        Parameters:
            d   (int): Secret key.
            G (Point): Generator point on an elliptical curve.
        """
        self.d   = d or Bytes.random(16).int()
        self.G   = G
        self.pub = pub

        if not pub:
            self.recompute_pub()



    def __repr__(self):
        return f"<ECDHE: d={self.d}, pub={self.pub}, G={self.G}>"

    def __str__(self):
        return self.__repr__()


    def recompute_pub(self) -> Point:
        """
        Gets the challenge.

        Returns:
            Point: The challenge.
        """
        self.pub = self.d * self.G


    def derive_point(self, challenge: Point) -> Point:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (Point): The other instance's challenge.
        
        Returns:
            Point: Shared key.
        """
        return self.d * challenge


    def derive_key(self, challenge: Point) -> Bytes:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (Point): The other instance's challenge.
        
        Returns:
            Bytes: Shared key.
        """
        return Bytes(int((self.d * challenge).x) % self.G.curve.p).zfill((self.G.curve.p.bit_length() + 7) // 8)
