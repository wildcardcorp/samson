from samson.padding.pkcs7 import PKCS7
from samson.utilities.bytes import Bytes
import unittest

class PKCS7TestCase(unittest.TestCase):
    def test_gauntlet(self):
        for block_size in range(8, 32):
            pkcs = PKCS7(block_size)

            for _ in range(1000):
                plaintext = Bytes.random(Bytes.random(1).int() % block_size)
                self.assertEqual(pkcs.unpad(pkcs.pad(plaintext)), plaintext)


    def test_correctness(self):
        for block_size in range(8, 32):
            pkcs = PKCS7(block_size)

            for i in range(block_size):
                padded = pkcs.pad(i * b'\xfe')
                self.assertTrue(all([padding == (i or block_size) for padding in padded[block_size:]]))
                self.assertEqual(len(padded) % block_size, 0)
