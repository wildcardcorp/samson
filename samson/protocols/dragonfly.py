from samson.utilities.bytes import Bytes
from samson.utilities.math import mod_inv
from samson.hashes.sha2 import SHA256
from samson.protocols.diffie_hellman import DiffieHellman
from types import FunctionType

# https://asecuritysite.com/encryption/dragonfly
# https://tools.ietf.org/html/draft-harkins-tls-dragonfly-04
class Dragonfly(object):
    """
    Dragonfly zero-knowledge proof.

    Used in WPA3.
    """

    def __init__(self, key: bytes, H: FunctionType=SHA256().hash, q: int=DiffieHellman.MODP_2048):
        """
        Parameters:
            key (bytes): Bytes-like object shared by both parties to authenticate each other.
            H    (func): Cryptographic hash function. Takes in bytes and returns the hash digest.
            q     (int): Modulus.
        """
        self.key = key
        self.q = q
        self.A = Bytes.random(16).to_int()
        self.a = Bytes.random(16).to_int()
        self.H = H


    def __repr__(self):
        return f"<Dragonfly: key={self.key}, H={self.H}, A={self.A}, a={self.a}, q={self.q}>"

    def __str__(self):
        return self.__repr__()


    def get_challenge(self) -> (int, int):
        """
        Gets the challenge.

        Returns:
            (int, int): The challenge.
        """
        sA = self.a + self.A

        PE = self.H(self.key).int()
        eA = mod_inv(pow(PE, self.A, self.q), self.q)
        return pow(PE, sA, self.q), eA



    def derive_key(self, challenge: (int, int)) -> int:
        """
        Derives the shared key from the other instance's challenge.

        Parameters:
            challenge (int, int): The other instance's challenge.
        
        Returns:
            int: Shared key.
        """
        PEsB, eB = challenge
        return pow(PEsB * eB, self.a, self.q)
