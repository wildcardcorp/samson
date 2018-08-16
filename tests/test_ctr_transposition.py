#!/usr/bin/python3
from samson.primitives.aes_ctr import AES_CTR
from samson.primitives.xor import decrypt 
from samson.utilities import gen_rand_key, levenshtein_distance
from samson.attacks.ctr_transposition_attack import CTRTranspositionAttack
from samson.analyzers.english_analyzer import EnglishAnalyzer
import base64
import struct
import unittest

block_size = 16
key = gen_rand_key(block_size)

def encrypt(secret):
    aes = AES_CTR(key, struct.pack('Q', 0))
    return aes.encrypt(secret)


class CTRTranspositionTestCase(unittest.TestCase):
    def test_transposition_attack(self):
        self.maxDiff = None

        with open('tests/test_ctr_transposition.txt') as f:
            secrets = [base64.b64decode(line.strip().encode()) for line in f.readlines()]

        ciphertexts = [encrypt(secret) for secret in secrets]

        analyzer = EnglishAnalyzer()
        attack = CTRTranspositionAttack(analyzer, decrypt, block_size)
        recovered_plaintexts = attack.execute(ciphertexts)

        #print(recovered_plaintexts)
        avg_distance = sum([levenshtein_distance(a,b) for a,b in zip(recovered_plaintexts, [bytearray(secret[:53]) for secret in secrets])]) / len(secrets)
        self.assertLessEqual(avg_distance, 2)
        #self.assertEqual(recovered_plaintexts, [bytearray(secret[:53]) for secret in secrets])
