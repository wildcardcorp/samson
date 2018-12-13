from fastecdsa.curve import P256
from fastecdsa.point import Point
from samson.utilities.general import rand_bytes

class ECDHE(object):
    """
    Elliptical curve Diffie-Hellman (Ephemeral).
    """

    def __init__(self, key: int=None, G: Point=P256.G):
        """
        Parameters:
            key (int): Secret key.
            G (Point): Generator point on an elliptical curve.
        """
        self.key = key or int.from_bytes(rand_bytes(), 'big')
        self.G = G



    def __repr__(self):
        return f"<ECDHE: key={self.key}, G={self.G}>"

    def __str__(self):
        return self.__repr__()



    def get_challenge(self) -> Point:
        """
        Gets the challenge.

        Returns:
            Point: The challenge.
        """
        return self.key * self.G



    def derive_key(self, challenge: Point) -> Point:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (Point): The other instance's challenge.
        
        Returns:
            Point: Shared key.
        """
        return self.key * challenge
