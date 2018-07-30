#!/usr/bin/python3
from Crypto.Random import random
from samson.primitives.aes_cbc import encrypt_aes_cbc, decrypt_aes_cbc
from samson.utilities import get_blocks, xor_buffs, gen_rand_key, pkcs7_unpad
from samson.attacks.cbc_padding_oracle_attack import CBCPaddingOracleAttack
from samson.oracles.padding_oracle import PaddingOracle
import base64
import struct
import unittest

block_size = 16
key = gen_rand_key(block_size)
iv = gen_rand_key(block_size)

plaintext_strings = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]

#chosen_plaintext = random.choice(plaintext_strings)
chosen_plaintext = plaintext_strings[0]


def encrypt_data():
    return encrypt_aes_cbc(key, iv, base64.b64decode(chosen_plaintext.encode()), block_size=block_size)


def decrypt_data(data):
    try:
        decrypt_aes_cbc(key, iv, data, block_size=block_size)
        return True
    except Exception as e:
        if 'Invalid padding' in str(e):
            return False
        raise e


class CBCPaddingOracleTestCase(unittest.TestCase):
    def test_paddingattack(self):
        print(base64.b64decode(chosen_plaintext.encode()))
        ciphertext = encrypt_data()
        assert decrypt_data(ciphertext) == True

        attack = CBCPaddingOracleAttack(PaddingOracle(decrypt_data), iv, block_size=block_size)
        recovered_plaintext = attack.execute(ciphertext)

        print(recovered_plaintext)
        self.assertEqual(base64.b64decode(chosen_plaintext.encode()), recovered_plaintext)