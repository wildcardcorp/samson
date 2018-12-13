from samson.utilities.bytes import Bytes
from math import ceil
from types import FunctionType


class CTR(object):
    """Counter block cipher mode."""

    def __init__(self, encryptor: FunctionType, nonce: bytes, block_size: int):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            nonce    (bytes): Bytes-like nonce.
            block_size (int): Block size of the underlying encryption algorithm.
        """
        self.encryptor = encryptor
        self.nonce = Bytes.wrap(nonce)
        self.block_size = block_size
        self.counter = 0
        self.byteorder = self.nonce.byteorder


    def __repr__(self):
        return f"<CTR: encryptor={self.encryptor}, nonce={self.nonce}, counter={self.counter}, block_size={self.block_size}, byteorder={self.byteorder}>"

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
        keystream = Bytes(b'')

        num_blocks = ceil(len(plaintext) / self.block_size)
        for _ in range(num_blocks):
            keystream += self.encryptor(self.nonce + self.counter.to_bytes(self.block_size - len(self.nonce), self.byteorder))
            self.counter += 1

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
