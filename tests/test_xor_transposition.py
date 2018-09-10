#!/usr/bin/python3
from samson.primitives.aes_ctr import AES_CTR
from samson.primitives.xor import decrypt 
from samson.utilities import gen_rand_key, levenshtein_distance
from samson.attacks.xor_transposition_attack import XORTranspositionAttack
from samson.analyzers.english_analyzer import EnglishAnalyzer
from Crypto.Cipher import ARC4
import base64
import struct
import unittest

block_size = 16
key = gen_rand_key(block_size)

def encrypt_ctr(secret):
    aes = AES_CTR(key, struct.pack('Q', 0))
    return aes.encrypt(secret)


def encrypt_rc4(secret):
    cipher = ARC4.new(key)
    return cipher.encrypt(secret)


class XORTranspositionTestCase(unittest.TestCase):
    def test_transposition_attack(self):
        self.maxDiff = None

        with open('tests/test_ctr_transposition.txt') as f:
            secrets = [base64.b64decode(line.strip().encode()) for line in f.readlines()]

        for encryptor in [encrypt_rc4, encrypt_ctr]:
            ciphertexts = [encryptor(secret) for secret in secrets]

            analyzer = EnglishAnalyzer()
            attack = XORTranspositionAttack(analyzer, block_size)
            recovered_plaintexts = attack.execute(ciphertexts)

            #print(recovered_plaintexts)
            avg_distance = sum([levenshtein_distance(a,b) for a,b in zip(recovered_plaintexts, [bytearray(secret[:53]) for secret in secrets])]) / len(secrets)
            self.assertLessEqual(avg_distance, 2)
