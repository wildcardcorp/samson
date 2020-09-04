from samson.math.general import mod_inv, random_int_between
from samson.hashes.sha2 import SHA256
from samson.protocols.diffie_hellman import DiffieHellman
from samson.utilities.bytes import Bytes
from samson.core.primitives import KeyExchangeAlg, Primitive
from samson.core.metadata import FrequencyType, UsageType
from samson.ace.decorators import register_primitive
from types import FunctionType

# https://asecuritysite.com/encryption/dragonfly
# https://tools.ietf.org/html/draft-harkins-tls-dragonfly-04
@register_primitive()
class Dragonfly(KeyExchangeAlg):
    """
    Dragonfly zero-knowledge proof.

    Used in WPA3.
    """

    USAGE_TYPE      = UsageType.WIRELESS
    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, key: bytes=None, H: FunctionType=SHA256().hash, q: int=DiffieHellman.MODP_2048):
        """
        Parameters:
            key (bytes): Bytes-like object shared by both parties to authenticate each other.
            H    (func): Cryptographic hash function. Takes in bytes and returns the hash digest.
            q     (int): Modulus.
        """
        Primitive.__init__(self)
        self.key = key or Bytes(random_int_between(1, q))
        self.q = q
        self.A = random_int_between(1, q)
        self.a = random_int_between(1, q)
        self.H = H


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
