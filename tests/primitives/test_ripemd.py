from samson.hashes.ripemd160 import RIPEMD160
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class RIPEMD160TestCase(unittest.TestCase):
    def test_ripemd160(self):
        ripe = RIPEMD160()

        for i in range(258):
            for _ in range(10):
                test_bytes = Bytes.random(i)
                self.assertEqual(ripe.hash(test_bytes), hashlib.new('ripemd160', test_bytes).digest())
