from samson.protocols.diffie_hellman import DiffieHellman
from samson.utilities.bytes import Bytes
from samson.math.general import mod_inv, random_int_between
from samson.core.primitives import NumberTheoreticalAlg, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive

@register_primitive()
class ElGamal(NumberTheoreticalAlg):
    """
    ElGamal public key encryption
    """

    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.KEY, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda elgamal: elgamal.p.bit_length()))
    USAGE_FREQUENCY = FrequencyType.UNUSUAL

    def __init__(self, g: int=2, p: int=DiffieHellman.MODP_2048, key: int=None):
        """
        Parameters:
            g   (int): Generator.
            p   (int): Prime modulus.
            key (int): Key.
        """
        Primitive.__init__(self)

        self.key = key or random_int_between(1, p)
        self.g   = g
        self.p   = p
        self.pub = pow(self.g, self.key, self.p)



    def encrypt(self, plaintext: bytes, k: int=None) -> (int, int):
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Message to encrypt.
            k           (int): (Optional) Ephemeral key.

        Returns:
            (int, int): Formatted as (ephemeral key, ciphertext).
        
        References:
            https://en.wikipedia.org/wiki/ElGamal_encryption
        """
        K_e = k or random_int_between(1, self.p)
        c_1 = pow(self.g, K_e, self.p)
        s   = pow(self.pub, K_e, self.p)
        plaintext = Bytes.wrap(plaintext)
        return c_1, (s * plaintext.int()) % self.p



    def decrypt(self, key_and_ciphertext: (int ,int)) -> Bytes:
        """
        Decrypts `key_and_ciphertext`.

        Parameters:
            key_and_ciphertext ((int, int)): Ephemeral key and ciphertext.
        
        Returns:
            Bytes: Plaintext.
        """
        c_1, ciphertext = key_and_ciphertext
        s = pow(c_1, self.key, self.p)
        return Bytes((mod_inv(s, self.p) * ciphertext) % self.p)
