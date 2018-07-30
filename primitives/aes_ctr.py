#!/usr/bin/python3
from samson.utilities import xor_buffs
from Crypto.Cipher import AES
from math import ceil
import struct
import base64

class AES_CTR:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.counter = 0
        self.encryptor = AES.new(key, AES.MODE_ECB)
        self.block_size = 16

    def encrypt(self, plaintext):
        keystream = b''
        
        num_blocks = ceil(len(plaintext) / self.block_size)
        for block in range(num_blocks):
            keystream += self.encryptor.encrypt(self.nonce + struct.pack('Q', self.counter))
            self.counter += 1

        return xor_buffs(keystream[:len(plaintext)], plaintext)


if __name__ == '__main__':
    ciphertext = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    aes = AES_CTR('YELLOW SUBMARINE', struct.pack('Q', 0))
    print(aes.encrypt(ciphertext))
