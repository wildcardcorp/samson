from samson.hashes.sha2 import SHA2
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class SHA2TestCase(unittest.TestCase):
    def test_sha2(self):
        for hash_type, reference_method in [(224, hashlib.sha224), (256, hashlib.sha256), (384, hashlib.sha384), (512, hashlib.sha512)]:
            for i in range(9):
                sha2 = SHA2(hash_type)
                
                for _ in range(100):
                    in_bytes = Bytes.random(i * 32)
                    self.assertEqual(sha2.hash(in_bytes), reference_method(in_bytes).digest())