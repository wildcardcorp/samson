from samson.hashes.sha1 import SHA1
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class SHA1TestCase(unittest.TestCase):
    def test_sha1(self):
        sha1 = SHA1()
        for i in range(9):
            for _ in range(100):
                in_bytes = Bytes.random(i * 32)
                self.assertEqual(sha1.hash(in_bytes), hashlib.sha1(in_bytes).digest())
