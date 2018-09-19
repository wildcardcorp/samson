from Crypto.Cipher import AES
from samson.utilities.manipulation import get_blocks
#xor_buffs,
from samson.utilities.padding import pkcs7_pad, pkcs7_unpad
from samson.utilities.bytes import Bytes


class CBC(object):
    def __init__(self, encryptor, decryptor, iv, block_size):
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.iv = iv
        self.block_size = block_size


    def encrypt(self, plaintext, pad=True):
        plaintext = Bytes.wrap(plaintext)

        if pad:
            plaintext = pkcs7_pad(plaintext, self.block_size)

        ciphertext = Bytes(b'')
        last_block = self.iv

        for block in get_blocks(plaintext, self.block_size):
            enc_block = self.encryptor(bytes(last_block ^ block))
            ciphertext += enc_block
            last_block = enc_block
        
        return ciphertext


    def decrypt(self, ciphertext, unpad=True):
        plaintext = b''

        last_block = self.iv
        for block in get_blocks(ciphertext, self.block_size):
            enc_block = last_block ^ Bytes.wrap(self.decryptor(block))
            plaintext += enc_block
            last_block = block

        if unpad: plaintext = pkcs7_unpad(plaintext, self.block_size)
        return plaintext
