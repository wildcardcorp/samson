from samson.hashes.md5 import MD5
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class MD5TestCase(unittest.TestCase):
    def test_md5(self):
        md5 = MD5()
        for i in range(9):
            for _ in range(100):
                in_bytes = Bytes.random(i * 32)
                self.assertEqual(md5.hash(in_bytes), hashlib.md5(in_bytes).digest())
