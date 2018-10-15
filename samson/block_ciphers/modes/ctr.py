from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from math import ceil


class CTR(object):
    def __init__(self, encryptor, nonce, block_size):
        self.encryptor = encryptor
        self.nonce = Bytes.wrap(nonce)
        self.block_size = block_size
        self.counter = 0
        self.byteorder = self.nonce.byteorder


    def __repr__(self):
        return f"<CTR: encryptor={self.encryptor}, nonce={self.nonce}, counter={self.counter}, block_size={self.block_size}, byteorder={self.byteorder}>"


    def __str__(self):
        return self.__repr__()

    def encrypt(self, plaintext):
        keystream = Bytes(b'')

        num_blocks = ceil(len(plaintext) / self.block_size)
        for _ in range(num_blocks):
            keystream += self.encryptor(self.nonce + self.counter.to_bytes(self.block_size - len(self.nonce), self.byteorder))
            self.counter += 1

        return keystream[:len(plaintext)] ^ plaintext


    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)