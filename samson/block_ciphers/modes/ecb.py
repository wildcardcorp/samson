from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from samson.padding.pkcs7 import PKCS7
from types import FunctionType


class ECB(object):
    """Electronic codebook block cipher mode."""

    def __init__(self, encryptor: FunctionType, decryptor: FunctionType, block_size: int):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            decryptor (func): Function that takes in a ciphertext and returns a plaintext.
            block_size (int): Block size of the underlying encryption algorithm.
        """
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.block_size = block_size
        self.padder = PKCS7(block_size)


    def __repr__(self):
        return f"<ECB: encryptor={self.encryptor}, decryptor={self.decryptor}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    def encrypt(self, plaintext: bytes, pad: bool=True) -> Bytes:
        """
        Encrypts `plaintext`.
        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
            pad        (bool): Pads the plaintext with PKCS7.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        if pad:
            plaintext = self.padder.pad(plaintext)


        ciphertext = Bytes(b'')
        for block in get_blocks(plaintext, self.block_size):
            ciphertext += self.encryptor(block)

        return ciphertext



    def decrypt(self, ciphertext: bytes, unpad: bool=True) -> Bytes:
        """
        Decrypts `ciphertext`.
        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
            unpad       (bool): Unpads the plaintext with PKCS7.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        plaintext = Bytes(b'')
        for block in get_blocks(ciphertext, self.block_size):
            plaintext += self.decryptor(block)


        if unpad:
            plaintext = self.padder.unpad(plaintext)

        return plaintext
