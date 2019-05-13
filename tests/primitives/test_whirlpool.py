from samson.hashes.whirlpool import Whirlpool
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class WhirlpoolTestCase(unittest.TestCase):
    def test_whirlpool(self):
        whirlpool = Whirlpool()
        for i in range(9):
            for j in range(100):
                in_bytes = Bytes.random(i * j)
                self.assertEqual(whirlpool.hash(in_bytes), hashlib.new('whirlpool', in_bytes).digest())
