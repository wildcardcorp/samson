from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from types import FunctionType

class CFB(object):
    """Cipher feedback block cipher mode."""

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


    def __repr__(self):
        return f"<CFB: encryptor={self.encryptor}, iv={self.iv}, block_size={self.block_size}>"


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
        ciphertext = b''
        plaintext = Bytes.wrap(plaintext)

        last_block = self.iv

        for block in get_blocks(plaintext, self.block_size, allow_partials=True):
            enc_block = self.encryptor(bytes(last_block))[:len(block)] ^ block
            ciphertext += enc_block
            last_block = enc_block

        return ciphertext



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        plaintext = b''
        ciphertext = Bytes.wrap(ciphertext)

        last_block = self.iv

        for block in get_blocks(ciphertext, self.block_size, allow_partials=True):
            enc_block = self.encryptor(bytes(last_block))[:len(block)] ^ block
            plaintext += enc_block
            last_block = block

        return plaintext
