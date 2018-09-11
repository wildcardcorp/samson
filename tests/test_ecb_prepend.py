#!/usr/bin/python3
import struct
import base64
from Crypto.Cipher import AES
from samson.utilities.padding import pkcs7_pad, pkcs7_unpad
from samson.utilities.general import rand_bytes
from samson.oracles.stateless_block_encryption_oracle import StatelessBlockEncryptionOracle
from samson.attacks.ecb_prepend_attack import ECBPrependAttack
import unittest

block_size = 16

def encrypt_aes_ecb(key, message):
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7_pad(message, block_size=block_size))


key = rand_bytes(block_size)
unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'.encode())


def encrypt_rand_ecb(message):
    mod_plain = message + unknown_string
    return encrypt_aes_ecb(key, mod_plain)


class ECBPrependAttackTestCase(unittest.TestCase):
    def test_prepend_attack(self):
        # Sanity check: is the padding correct?
        pkcs7_unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypt_rand_ecb(b'')), block_size=block_size)

        attack = ECBPrependAttack(StatelessBlockEncryptionOracle(encrypt_rand_ecb))
        recovered_plaintext = attack.execute()
        self.assertEqual(unknown_string, recovered_plaintext)
        print(recovered_plaintext)
