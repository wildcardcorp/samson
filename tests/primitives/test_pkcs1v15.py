from samson.padding.pkcs1v15 import PKCS1v15
from samson.utilities.bytes import Bytes
import unittest

class PKCS1v15TestCase(unittest.TestCase):
    def test_gauntlet(self):
        pkcs = PKCS1v15(256)

        for _ in range(1000):
            plaintext = Bytes.random(8)
            self.assertEqual(pkcs.unpad(pkcs.pad(plaintext)), plaintext)


    def test_input_too_big(self):
        pkcs = PKCS1v15(88)
        plaintext = Bytes.random(8)

        with self.assertRaises(AssertionError):
            pkcs.pad(plaintext)


    def test_nonzero_padding(self):
        pkcs = PKCS1v15(1024)

        for _ in range(1000):
            padding = pkcs.pad(b'')

            self.assertEqual(0, padding[0])
            self.assertEqual(0, padding[-1])

            self.assertFalse(b'\x00' in padding[1:-1])
