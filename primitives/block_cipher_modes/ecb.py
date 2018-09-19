from samson.utilities.padding import pkcs7_pad, pkcs7_unpad
from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes


class ECB(object):
    def __init__(self, encryptor, decryptor, block_size):
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.block_size = block_size


    def encrypt(self, plaintext, pad=True):
        if pad:
            plaintext = pkcs7_pad(plaintext, self.block_size)

        
        ciphertext = Bytes(b'')
        for block in get_blocks(plaintext, self.block_size):
            ciphertext += self.encryptor(block)

        return ciphertext
        

    def decrypt(self, ciphertext, unpad=True):
        plaintext = Bytes(b'')
        for block in get_blocks(ciphertext, self.block_size):
            plaintext += self.decryptor(block)
        
        if unpad:
            plaintext = pkcs7_unpad(plaintext)
        
        return plaintext