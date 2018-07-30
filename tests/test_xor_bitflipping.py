#!/usr/bin/python3
import urllib.parse
from samson.utilities import gen_rand_key
from samson.primitives.aes_ctr import AES_CTR
from samson.primitives.aes_cbc import encrypt_aes_cbc, decrypt_aes_cbc
from samson.attacks.xor_bitflipping_attack import XORBitflippingAttack
from samson.oracles.encryption_oracle import EncryptionOracle
import struct
import time
import unittest

block_size = 16
key = gen_rand_key(block_size)
iv = gen_rand_key(block_size)
nonce = gen_rand_key(block_size // 2)

def format_data(data):
    return ("comment1=cooking%20MCs;userdata=" + urllib.parse.quote(data) + ";comment2=%20like%20a%20pound%20of%20bacon").encode()


# CBC Functions
def encrypt_data_cbc(data):
    return encrypt_aes_cbc(key, iv, format_data(data), block_size=block_size)


def login_cbc(ciphertext):
    print(decrypt_aes_cbc(key, iv, ciphertext, block_size=block_size))
    return b';admin=true;' in decrypt_aes_cbc(key, iv, ciphertext, block_size=block_size)


# CTR Functions
def encrypt_data_ctr(data):
    return AES_CTR(key, nonce, block_size=block_size).encrypt(format_data(data))


def login_ctr(ciphertext):
    return b';admin=true;' in AES_CTR(key, nonce, block_size=block_size).encrypt(ciphertext)


class XORBitFlipTestCase(unittest.TestCase):
    def test_bitflip(self):
        oracle = EncryptionOracle(encrypt_data_cbc)
        attack = XORBitflippingAttack(oracle, block_size=block_size)
        forged_request = attack.execute(b'hiya;admin=true;' * (block_size // 16), 16)

        if(login_cbc(bytes(forged_request))):
            print('Success! We\'re admin!')
        
        self.assertTrue(login_cbc(bytes(forged_request)))


    def test_ctr_bitflip(self):
        oracle = EncryptionOracle(encrypt_data_ctr)
        attack = XORBitflippingAttack(oracle, block_size=block_size)
        forged_request = attack.execute(b'hiya;admin=true;' * (block_size // 16), 32)

        if(login_ctr(bytes(forged_request))):
            print('Success! We\'re admin!')

        self.assertTrue(login_ctr(bytes(forged_request)))