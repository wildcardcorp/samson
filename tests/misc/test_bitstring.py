from samson.utilities.bitstring import Bitstring
from samson.utilities.bytes import Bytes
import unittest

# TEST BYTEORDER
# Validates Bitstring against Bytes to ensure a uniform interface
class BitstringTestCase(unittest.TestCase):
    def _run_binary_gauntlet(self, func):
        for _ in range(1000):
            bytes_a = Bytes.random(16)
            bytes_b = Bytes.random(16)

            bs_a = Bitstring(bytes_a).zfill(128)
            bs_b = Bitstring(bytes_b).zfill(128)

            bs_result = func(bs_a, bs_b).int()
            byte_result = func(bytes_a, bytes_b).int()
            right_bs_result = func(bs_b, bs_a).int()

            if bs_result != byte_result or bs_result != right_bs_result:
                print(bytes_a)
                print(bytes_b)

            self.assertEqual(bs_result, byte_result)
            self.assertEqual(bs_result, right_bs_result)



    def _run_unary_gauntlet(self, func, iterations=1000):
        for _ in range(iterations):
            bytes_a = Bytes.random(16)

            bs_a = Bitstring(bytes_a).zfill(128)

            bs_result = func(bs_a).int()
            byte_result = func(bytes_a).int()

            if bs_result != byte_result:
                print(bytes_a)

            self.assertEqual(bs_result, byte_result)



    def test_bytes_conversion_gauntlet(self):
        for _ in range(1000):
            test_bytes = Bytes.random(16)
            bs = Bitstring(test_bytes)
            bs_bytes = bs.bytes().zfill(16)

            if test_bytes != bs_bytes:
                print(test_bytes)
                print(bs_bytes)

            self.assertEqual(test_bytes, bs_bytes)



    def test_xor_gauntlet(self):
        self._run_binary_gauntlet(lambda x, y: x ^ y)


    def test_and_gauntlet(self):
        self._run_binary_gauntlet(lambda x, y: x & y)


    def test_or_gauntlet(self):
        self._run_binary_gauntlet(lambda x, y: x | y)


    def test_invert_gauntlet(self):
        self._run_unary_gauntlet(lambda x: ~x)


    def test_lshift_gauntlet(self):
        for i in range(128):
            self._run_unary_gauntlet(lambda x: x << i, iterations=32)


    def test_rshift_gauntlet(self):
        for i in range(128):
            self._run_unary_gauntlet(lambda x: x >> i, iterations=32)


    def test_lrot_gauntlet(self):
        for i in range(128):
            self._run_unary_gauntlet(lambda x: x.lrot(i), iterations=32)


    def test_rrot_gauntlet(self):
        for i in range(128):
            self._run_unary_gauntlet(lambda x: x.rrot(i), iterations=32)
