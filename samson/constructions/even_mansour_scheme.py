from samson.utilities.bytes import Bytes
from types import FunctionType

class EvenMansourScheme(object):
    """
    Block cipher construction built from a prewhitening key, unkeyed psuedorandom permutation, and postwhitening key.
    """

    def __init__(self, F: FunctionType, K1: bytes, K2: bytes=None):
        """
        Parameters:
            F   (func): Unkeyed psuedorandom permutation.
            K1 (bytes): Bytes-like object to key the cipher.
            K2 (bytes): (Optional) Bytes-like object to key the cipher.
        """
        self.F = F
        self.K1 = Bytes.wrap(K1)
        self.K2 = Bytes.wrap(K2 or K1)
        self.block_size = len(self.K1)


    def __repr__(self):
        return f"<EvenMansourScheme F={self.F}, K1={self.K1}, K2={self.K2}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        k1_p = self.K1 ^ plaintext
        f_p = self.F(k1_p)
        return f_p ^ self.K2



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        k2_p = self.K2 ^ ciphertext
        f_p = self.F(k2_p)
        return f_p ^ self.K1
