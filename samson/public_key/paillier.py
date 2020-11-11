from samson.math.general import find_prime, mod_inv, gcd, random_int
from samson.utilities.bytes import Bytes
from samson.core.primitives import EncryptionAlg


class Paillier(EncryptionAlg):
    """
    Paillier public key cryptosystem

    Partially homomorphic encryption. Supports addition and multiplication.
    """

    def __init__(self, p: int=None, q: int=None):
        """
        Parameters:
            p (int): Large prime.
            q (int): Large prime.
        """
        self.p = p or find_prime(512)
        self.q = q or find_prime(512)
        self.n = self.p * self.q

        self.phi = (self.p - 1) * (self.q - 1)
        self.g = self.n + 1
        self.priv = mod_inv(self.phi, self.n)


    def L(self, x: int) -> int:
        return (x - 1) // self.n

    def __reprdir__(self):
        return ['priv', 'p', 'q', 'n', 'g', 'phi']


    def encrypt(self, plaintext: bytes) -> int:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Plaintext.
        
        Returns:
            int: Ciphertext.
        """
        m = Bytes.wrap(plaintext).to_int()
        assert m < self.n

        r = random_int(self.n)
        while gcd(r, self.n) != 1:
            r = random_int(self.n)

        n_sqr = self.n ** 2
        return pow(self.g, m, n_sqr) * pow(r, self.n, n_sqr)



    def decrypt(self, ciphertext: int) -> Bytes:
        """
        Decrypts `ciphertext` back into plaintext.

        Parameters:
            ciphertext (int): Ciphertext.
        
        Returns:
            Bytes: Decrypted plaintext.
        """
        return Bytes((self.L(pow(ciphertext, self.phi, self.n ** 2)) * self.priv) % self.n)
