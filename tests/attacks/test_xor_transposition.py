#!/usr/bin/python3
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ctr import CTR

from samson.utilities.general import rand_bytes
from samson.analysis.general import levenshtein_distance
from samson.attacks.xor_transposition_attack import XORTranspositionAttack
from samson.analyzers.english_analyzer import EnglishAnalyzer
from samson.stream_ciphers.rc4 import RC4
import base64
import unittest
import os

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)

key_size = 16
block_size = 16
key = rand_bytes(key_size)

def encrypt_ctr(secret):
    return CTR(Rijndael(key), int.to_bytes(0, block_size // 2, 'big')).encrypt(secret)


def encrypt_rc4(secret):
    cipher = RC4(key)
    return cipher.generate(len(secret)) ^ secret


class XORTranspositionTestCase(unittest.TestCase):
    def try_encryptor(self, encryptor):
        with open(f'{os.path.dirname(os.path.abspath(__file__))}/test_ctr_transposition.txt') as f:
            secrets = [base64.b64decode(line.strip().encode()) for line in f.readlines()]

        ciphertexts = [encryptor(secret) for secret in secrets]

        analyzer = EnglishAnalyzer()
        attack   = XORTranspositionAttack(analyzer)
        recovered_plaintexts = attack.execute(ciphertexts)

        print(recovered_plaintexts)
        avg_distance = sum([levenshtein_distance(a,b) for a,b in zip(recovered_plaintexts, [bytearray(secret[:53]) for secret in secrets])]) / len(secrets)
        self.assertLessEqual(avg_distance, 2)


    # Here just for reference. No reason to test against two stream ciphers.
    # def test_rc4_attack(self):
    #     self.try_encryptor(encrypt_rc4)


    def test_ctr_attack(self):
        self.try_encryptor(encrypt_ctr)
