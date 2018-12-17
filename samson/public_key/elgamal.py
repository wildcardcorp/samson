from samson.protocols.diffie_hellman import DiffieHellman
from samson.utilities.bytes import Bytes
from samson.utilities.math import mod_inv

class ElGamal(object):
    """
    ElGamal public key encryption
    """

    def __init__(self, g: int=2, p: int=DiffieHellman.MODP_2048, key: int=None):
        """
        Parameters:
            g   (int): Generator.
            p   (int): Prime modulus.
            key (int): Key.
        """
        self.key = key or Bytes.random().int()
        self.g = g
        self.p = p
        self.pub = pow(self.g, self.key, self.p)


    def __repr__(self):
        return f"<ElGamal: key={self.key}, g={self.g}, p={self.p}, pub={self.pub}>"


    def __str__(self):
        return self.__repr__()


    # https://en.wikipedia.org/wiki/ElGamal_encryption
    def encrypt(self, plaintext: bytes, k: int=None) -> (int, int):
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Message to encrypt.
            k           (int): (Optional) Ephemeral key.
        
        Returns:
            (int, int): Formatted as (ephemeral key, ciphertext).
        """
        K_e = k or max(1, Bytes.random().int() % self.p)
        c_1 = pow(self.g, K_e, self.p)
        s = pow(self.pub, K_e, self.p)
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
