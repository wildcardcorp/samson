#!/usr/bin/python3
import urllib.parse
from samson.utilities import gen_rand_key
from samson.primitives.aes_cbc import encrypt_aes_cbc, decrypt_aes_cbc
from samson.attacks.cbc_bitflipping_attack import CBCBitflippingAttack
from samson.oracles.cbc_encryption_oracle import CBCEncryptionOracle
import struct
import time
import unittest


key = gen_rand_key()
iv = gen_rand_key()

def format_data(data):
    return ("comment1=cooking%20MCs;userdata=" + urllib.parse.quote(data) + ";comment2=%20like%20a%20pound%20of%20bacon").encode()


def encrypt_data(data):
    return encrypt_aes_cbc(key, iv, format_data(data))


def login(ciphertext):
    print(decrypt_aes_cbc(key, iv, ciphertext))
    return b';admin=true;' in decrypt_aes_cbc(key, iv, ciphertext)


class CBCBitFlipTestCase(unittest.TestCase):
    def test_bitflip(self):
        oracle = CBCEncryptionOracle(encrypt_data)
        attack = CBCBitflippingAttack(oracle)
        forged_request = attack.execute(b'hiya;admin=true;')

        if(login(bytes(forged_request))):
            print('Success! We\'re admin!')