#!/usr/bin/python3
from Crypto.Cipher import AES
from samson.primitives.block_cipher_modes.ctr import CTR

from samson.utilities.general import rand_bytes
from samson.utilities.analysis import levenshtein_distance
from samson.attacks.xor_transposition_attack import XORTranspositionAttack
from samson.analyzers.english_analyzer import EnglishAnalyzer
from Crypto.Cipher import ARC4
import base64
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)

block_size = 16
key = rand_bytes(block_size)

def encrypt_ctr(secret):
    return CTR(AES.new(key, AES.MODE_ECB).encrypt, int.to_bytes(0, block_size // 2, 'big'), block_size).encrypt(secret)


def encrypt_rc4(secret):
    cipher = ARC4.new(key)
    return cipher.encrypt(secret)


class XORTranspositionTestCase(unittest.TestCase):
    def try_encryptor(self, encryptor):
        with open('tests/test_ctr_transposition.txt') as f:
            secrets = [base64.b64decode(line.strip().encode()) for line in f.readlines()]

        ciphertexts = [encryptor(secret) for secret in secrets]

        analyzer = EnglishAnalyzer()
        attack = XORTranspositionAttack(analyzer)
        recovered_plaintexts = attack.execute(ciphertexts)

        print(recovered_plaintexts)
        avg_distance = sum([levenshtein_distance(a,b) for a,b in zip(recovered_plaintexts, [bytearray(secret[:53]) for secret in secrets])]) / len(secrets)
        self.assertLessEqual(avg_distance, 2)


    def test_rc4_attack(self):
        self.try_encryptor(encrypt_rc4)

    
    def test_ctr_attack(self):
        self.try_encryptor(encrypt_ctr)