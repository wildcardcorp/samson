from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from math import ceil


class CTR(object):
    def __init__(self, encryptor, nonce, block_size):
        self.encryptor = encryptor
        self.nonce = nonce
        self.block_size = block_size
        self.counter = 0


    def encrypt(self, plaintext):
        keystream = Bytes(b'')

        num_blocks = ceil(len(plaintext) / self.block_size)
        for _ in range(num_blocks):
            keystream += self.encryptor(self.nonce + self.counter.to_bytes(self.block_size // 2, 'little'))
            self.counter += 1

        return keystream[:len(plaintext)] ^ plaintext


    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)