from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class SHA2TestCase(unittest.TestCase):
    def test_sha2(self):
        for hash_type, reference_method in [(SHA224, hashlib.sha224), (SHA256, hashlib.sha256), (SHA384, hashlib.sha384), (SHA512, hashlib.sha512)]:
            for i in range(9):
                sha2 = hash_type()
                
                for _ in range(100):
                    in_bytes = Bytes.random(i * 32)
                    self.assertEqual(sha2.hash(in_bytes), reference_method(in_bytes).digest())