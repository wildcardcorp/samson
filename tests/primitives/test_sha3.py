from samson.hashes.sha3 import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class SHA3TestCase(unittest.TestCase):
    def test_sha3(self):
        for hash_type, reference_method in [(SHA3_224, hashlib.sha3_224), (SHA3_256, hashlib.sha3_256), (SHA3_384, hashlib.sha3_384), (SHA3_512, hashlib.sha3_512)]:
            sha3 = hash_type()
            for i in range(9):
                for _ in range(100):
                    in_bytes = Bytes.random(i * 32)
                    self.assertEqual(sha3.hash(in_bytes), reference_method(in_bytes).digest())


    def test_shake(self):
        for hash_type, reference_method, length in [(SHAKE128, hashlib.shake_128, 256), (SHAKE256, hashlib.shake_256, 512)]:
            shake = hash_type(length)
            for i in range(9):
                for _ in range(100):
                    in_bytes = Bytes.random(i * 32)
                    self.assertEqual(shake.hash(in_bytes), reference_method(in_bytes).digest(length // 8))
