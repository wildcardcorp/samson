from samson.hashes.blake2 import BLAKE2b, BLAKE2s
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class BLAKE2TestCase(unittest.TestCase):
    def _run_test(self, test_hash, reference_method):
        for i in range(258):
            for _ in range(10):
                test_bytes = Bytes.random(i)
                self.assertEqual(test_hash.hash(test_bytes), reference_method(test_bytes).digest())


    def test_blake2b(self):
        self._run_test(BLAKE2b(), hashlib.blake2b)


    def test_blake2s(self):
        self._run_test(BLAKE2s(), hashlib.blake2s)
