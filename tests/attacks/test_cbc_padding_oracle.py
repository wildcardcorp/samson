#!/usr/bin/python3
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.cbc import CBC
from samson.padding.pkcs7 import PKCS7
from samson.utilities.general import rand_bytes
from samson.attacks.cbc_padding_oracle_attack import CBCPaddingOracleAttack
from samson.oracles.padding_oracle import PaddingOracle
from samson.utilities.exceptions import InvalidPaddingException
import random
import base64
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)

key_size = 16
block_size = 16
key = rand_bytes(key_size)
iv = rand_bytes(block_size)

aes = Rijndael(key)
cbc = CBC(aes, iv)
padder = PKCS7(block_size)

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
        _ = cbc.decrypt(bytes(data))
        return True
    except InvalidPaddingException as _:
        return False


class CBCPaddingOracleTestCase(unittest.TestCase):
    def test_paddingattack(self):
        ciphertext = encrypt_data()
        assert decrypt_data(ciphertext)

        attack = CBCPaddingOracleAttack(PaddingOracle(decrypt_data), block_size=block_size, threads=5)
        recovered_plaintext = attack.execute(bytes(ciphertext), iv=iv)

        recovered_plaintext = padder.unpad(recovered_plaintext)

        print(recovered_plaintext)
        self.assertEqual(base64.b64decode(chosen_plaintext.encode()), recovered_plaintext)



    def test_paddingattack_batch(self):
        ciphertext = encrypt_data()
        assert decrypt_data(ciphertext)

        def decrypt_batch(blocks):
            working_blocks = []
            for block in blocks:
                if decrypt_data(block):
                    working_blocks.append(block)

            return working_blocks[-1]

        attack = CBCPaddingOracleAttack(PaddingOracle(decrypt_batch), block_size=block_size, batch_requests=True)
        recovered_plaintext = attack.execute(bytes(ciphertext), iv=iv)

        recovered_plaintext = padder.unpad(recovered_plaintext)

        print(recovered_plaintext)
        self.assertEqual(base64.b64decode(chosen_plaintext.encode()), recovered_plaintext)
