from samson.block_ciphers.modes.ecb import ECB
from math import ceil
from types import FunctionType
from samson.utilities.bytes import Bytes

class KW(object):
    """Key wrap cipher mode."""
    RFC3394_IV = Bytes(0xA6A6A6A6A6A6A6A6)
    RFC5649_IV = Bytes(0xA65959A6)

    def __init__(self, encryptor: FunctionType, iv: bytes, block_size: int):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            iv       (bytes): Bytes-like initialization vector.
            block_size (int): Block size of the underlying encryption algorithm.
        """
        self.encryptor = encryptor
        self.iv = iv
        self.block_size = block_size
        self.ecb = ECB(encryptor, None, block_size)


    def __repr__(self):
        return f"<KW: encryptor={self.encryptor}, iv={self.iv}, block_size={self.block_size}>"

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
        num_blocks = ceil(len(plaintext) / self.block_size)
        keystream = self.ecb.encrypt(b'\x00' * self.block_size * num_blocks, False)

        return keystream[:len(plaintext)] ^ plaintext


    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        return self.encrypt(ciphertext)
