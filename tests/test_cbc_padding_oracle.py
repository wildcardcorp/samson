#!/usr/bin/python3
from Crypto.Random import random
from Crypto.Cipher import AES
from samson.primitives.block_cipher_modes.cbc import CBC
from samson.utilities.general import rand_bytes
from samson.attacks.cbc_padding_oracle_attack import CBCPaddingOracleAttack
from samson.oracles.padding_oracle import PaddingOracle
import base64
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)

block_size = 16
key = rand_bytes(block_size)
iv = rand_bytes(block_size)

aes = AES.new(key, AES.MODE_ECB)
cbc = CBC(aes.encrypt, aes.decrypt, iv, block_size)

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

chosen_plaintext = random.choice(plaintext_strings)


def encrypt_data():
    return cbc.encrypt(base64.b64decode(chosen_plaintext.encode()))


def decrypt_data(data):
    try:
        cbc.decrypt(bytes(data))
        return True
    except Exception as e:
        if 'Invalid padding' in str(e):
            return False
        raise e


class CBCPaddingOracleTestCase(unittest.TestCase):
    def test_paddingattack(self):
        ciphertext = encrypt_data()
        assert decrypt_data(ciphertext) == True

        attack = CBCPaddingOracleAttack(PaddingOracle(decrypt_data), iv, block_size=block_size)
        recovered_plaintext = attack.execute(bytes(ciphertext))

        print(recovered_plaintext)
        self.assertEqual(base64.b64decode(chosen_plaintext.encode()), recovered_plaintext)