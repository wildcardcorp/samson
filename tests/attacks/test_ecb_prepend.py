#!/usr/bin/python3
import base64
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ecb import ECB
from samson.padding.pkcs7 import PKCS7
from samson.utilities.general import rand_bytes
from samson.oracles.chosen_plaintext_oracle import ChosenPlaintextOracle
from samson.attacks.ecb_prepend_attack import ECBPrependAttack
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)

key_size   = 16
block_size = 16


key = rand_bytes(key_size)
unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'.encode())


def encrypt_rand_ecb(message):
    mod_plain = message + unknown_string
    return ECB(Rijndael(key)).encrypt(mod_plain)


class ECBPrependAttackTestCase(unittest.TestCase):
    def test_prepend_attack(self):
        attack = ECBPrependAttack(ChosenPlaintextOracle(encrypt_rand_ecb))
        recovered_plaintext = attack.execute()

        padder = PKCS7(block_size)
        recovered_plaintext = padder.unpad(recovered_plaintext)

        self.assertEqual(recovered_plaintext, unknown_string)
