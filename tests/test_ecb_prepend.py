#!/usr/bin/python3
import struct
import base64
from samson.utilities import gen_rand_key, pkcs7_pad
from Crypto.Cipher import AES
from samson.oracles.ecb_encryption_oracle import ECBEncryptionOracle
from samson.attacks.ecb_prepend_attack import ECBPrependAttack
import unittest

def encrypt_aes_ecb(key, message):
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7_pad(message))


key = gen_rand_key()
unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'.encode())


def encrypt_rand_ecb(message):
    mod_plain = message + unknown_string
    return encrypt_aes_ecb(key, mod_plain)


class ECBPrependAttackTestCase(unittest.TestCase):
    def test_prepend_attack(self):
        attack = ECBPrependAttack(ECBEncryptionOracle(encrypt_rand_ecb))
        recovered_plaintext = attack.execute()
        self.assertEqual(unknown_string, recovered_plaintext)
        print(recovered_plaintext)
