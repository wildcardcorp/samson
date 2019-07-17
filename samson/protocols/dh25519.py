from samson.math.algebra.curves.montgomery_curve import MontgomeryCurve
from samson.math.algebra.curves.named import Curve25519
from samson.utilities.bytes import Bytes

class DH25519(object):
    """
    Elliptical curve Diffie-Hellman using Montgomery curves.
    """

    def __init__(self, d: int=None, pub: int=None, base: int=None, curve: MontgomeryCurve=Curve25519):
        """
        Parameters:
            d                 (int): Secret key that will be clamped to the curve.
            base              (int): Base multiplier used in generating the challenge.
            curve (MontgomeryCurve): The curve used.
        """
        self.d     = Bytes.wrap(d or Bytes.random(32)).int()
        self.curve = curve
        self.key   = curve.clamp_to_curve(self.d)
        self.base  = base or curve.U

        self.pub   = pub

        if not pub:
            self.recompute_public()


    def __repr__(self):
        return f"<DH25519: d={self.d}, key={self.key}, pub={self.pub}, base={self.base}>"

    def __str__(self):
        return self.__repr__()



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
