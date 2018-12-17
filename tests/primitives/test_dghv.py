from samson.public_key.dghv import DGHV
from samson.utilities.bytes import Bytes
import unittest


class DGHVTestCase(unittest.TestCase):
    def test_enc_dec(self):
        dghv = DGHV()

        for i in range(1000000):
            c = dghv.encrypt(i % 2)
            self.assertEqual(dghv.decrypt(c), (i % 2))


    def test_xor(self):
        dghv = DGHV()

        for _ in range(1000):
            a, b = Bytes.random(4).to_int(), Bytes.random(4).to_int()
            a_bin = [int(char) for char in bin(a)[2:].zfill(32)]
            b_bin = [int(char) for char in bin(b)[2:].zfill(32)]

            a_c = [dghv.encrypt(a_int) for a_int in a_bin]
            b_c = [dghv.encrypt(b_int) for b_int in b_bin]

            xord = [a_int + b_int for a_int, b_int in zip(a_c, b_c)]
            assert int(''.join([str(dghv.decrypt(x_int)) for x_int in xord]), 2) == (a ^ b)
