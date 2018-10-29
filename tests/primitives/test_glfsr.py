from samson.prngs.glfsr import GLFSR
from samson.utilities.bytes import Bytes
import unittest

class GFLSRTestCase(unittest.TestCase):
    def test_crack(self):
        for i in range(4):
            for _ in range(1024):
                seed = Bytes.random(16).int()
                poly = Bytes.random(i + 1).int()
                start_clocks = Bytes.random(1).int()

                ref_lfsr = GLFSR(seed, poly)
                [ref_lfsr.clock() for _ in range(start_clocks)]

                out_bits = [ref_lfsr.clock() for _ in range(poly.bit_length() * 2)]
                cracked_lfsr = GLFSR.crack(out_bits)

                self.assertTrue(all([ref_lfsr.clock() == cracked_lfsr.clock() for _ in range(poly.bit_length() * 5)]))