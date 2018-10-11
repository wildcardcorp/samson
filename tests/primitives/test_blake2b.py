from samson.hashes.blake2b import BLAKE2b
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class BLAKE2bTestCase(unittest.TestCase):
    def test_blake2b(self):
        blake = BLAKE2b()

        for i in range(258):
            for j in range(10):
                test_bytes = Bytes.random(i)
                self.assertEqual(blake.hash(test_bytes), hashlib.blake2b(test_bytes).digest())