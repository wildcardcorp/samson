from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from samson.padding.pkcs7 import PKCS7
from types import FunctionType

class CBC(object):
    """Cipherblock chaining block cipher mode."""

    def __init__(self, encryptor: FunctionType, decryptor: FunctionType, iv: bytes, block_size: int):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            decryptor (func): Function that takes in a ciphertext and returns a plaintext.
            iv       (bytes): Bytes-like initialization vector.
            block_size (int): Block size of the underlying encryption algorithm.
        """
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.iv = iv
        self.block_size = block_size
        self.padder = PKCS7(block_size)


    def __repr__(self):
        return f"<CBC: encryptor={self.encryptor}, decryptor={self.decryptor}, iv={self.iv}, block_size={self.block_size}>"

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
        plaintext = Bytes.wrap(plaintext)


        if pad:
            plaintext = self.padder.pad(plaintext)


        if len(plaintext) % self.block_size != 0:
            raise Exception("Plaintext is not a multiple of the block size")

        ciphertext = Bytes(b'')
        last_block = self.iv

        for block in get_blocks(plaintext, self.block_size):
            enc_block = self.encryptor(bytes(last_block ^ block))
            ciphertext += enc_block
            last_block = enc_block

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
        plaintext = b''

        if len(ciphertext) % self.block_size != 0:
            raise Exception("Ciphertext is not a multiple of the block size")

        last_block = self.iv
        for block in get_blocks(ciphertext, self.block_size):
            enc_block = last_block ^ Bytes.wrap(self.decryptor(block))
            plaintext += enc_block
            last_block = block

        if unpad:
            plaintext = self.padder.unpad(plaintext)

        return plaintext
