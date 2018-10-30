from samson.prngs.lcg import LCG
from samson.utilities.bytes import Bytes
import unittest

class LCGTestCase(unittest.TestCase):
    def test_crack(self):
        for _ in range(10):
            seed = Bytes.random(16).int()

            ref_lcg = LCG(X=seed, a=1103515245, c=12345, m=2**31)
            outputs = [ref_lcg.generate() for _ in range(10)]

            cracked_lcg = LCG.crack(outputs)

            self.assertTrue(all([ref_lcg.generate() == cracked_lcg.generate() for _ in range(10000)]))

    
    def test_truncated_crack(self):
        for trunc_amount in range(1, 20, 2):
            seed = Bytes.random(16).int() % 2**31

            ref_lcg = LCG(X=seed, a=1103515245, c=12345, m=2**31)
            outputs = [ref_lcg.generate() >> trunc_amount for _ in range(20)]
            to_predict = [ref_lcg.generate() >> trunc_amount for _ in range(100)]

            cracked_lcg = LCG.crack_truncated(outputs, to_predict, multiplier=ref_lcg.a, increment=ref_lcg.c, modulus=ref_lcg.m, trunc_amount=trunc_amount)

            accuracy = sum([ref_lcg.generate() >> trunc_amount == cracked_lcg.generate() >> trunc_amount for _ in range(1000)]) / 1000
            self.assertGreater(accuracy, 0.9)
