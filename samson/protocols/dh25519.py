from samson.utilities.ecc import Curve25519, MontgomeryCurve
from samson.utilities.general import rand_bytes

class DH25519(object):
    """
    Elliptical curve Diffie-Hellman using Montgomery curves.
    """

    def __init__(self, key: int=None, base: int=None, curve: MontgomeryCurve=Curve25519()):
        """
        Parameters:
            key               (int): Secret key that will be clamped to the curve.
            base              (int): Base multiplier used in generating the challenge.
            curve (MontgomeryCurve): The curve used.
        """
        self.key = curve.clamp_to_curve(key or int.from_bytes(rand_bytes(32), 'big'))
        self.base = base or curve.U


    def __repr__(self):
        return f"<DH25519: key={self.key}, base={self.base}>"

    def __str__(self):
        return self.__repr__()


    def get_challenge(self) -> int:
        """
        Gets the challenge.

        Returns:
            int: The integer challenge representing an `x` value on the curve.
        """
        return self.key * self.base


    def derive_key(self, challenge: int) -> int:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (int): The other instance's challenge.
        
        Returns:
            int: Shared key.
        """
        return self.key * challenge
