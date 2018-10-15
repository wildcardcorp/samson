from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.cbc import CBC
from math import ceil


class OFB(object):
    def __init__(self, encryptor, iv, block_size):
        self.encryptor = encryptor
        self.iv = iv
        self.block_size = block_size
        self._cbc = CBC(encryptor, None, iv, block_size)

    def __repr__(self):
        return f"<OFB: encryptor={self.encryptor}, iv={self.iv}, block_size={self.block_size}>"


    def __str__(self):
        return self.__repr__()


    def encrypt(self, plaintext):
        num_blocks = ceil(len(plaintext) / self.block_size)
        keystream = self._cbc.encrypt(b'\x00' * self.block_size * num_blocks, False)

        return keystream[:len(plaintext)] ^ plaintext


    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)