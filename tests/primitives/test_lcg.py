from samson.prngs.lcg import LCG
from samson.utilities.bytes import Bytes
from tqdm import tqdm
import unittest


def wiki_lcg(modulus, a, c, seed):
    while True:
        seed = (a * seed + c) % modulus
        yield seed


class LCGTestCase(unittest.TestCase):
    def test_crack(self):
        for _ in range(10):
            seed = Bytes.random(16).int()

            ref_lcg = LCG(X=seed, a=1103515245, c=12345, m=2**31)
            outputs = [ref_lcg.generate() for _ in range(15)]

            cracked_lcg = LCG.crack(outputs)

            self.assertTrue(all([ref_lcg.generate() == cracked_lcg.generate() for _ in range(10000)]))


    def test_truncated_crack(self):
        for trunc_amount in tqdm(range(1, 10, 2)):
            seed = Bytes.random(16).int() % 2**31

            ref_lcg    = LCG(X=seed, a=1103515245, c=12345, m=2**31, trunc=trunc_amount)
            outputs    = [ref_lcg.generate() for _ in range(20)]
            to_predict = [ref_lcg.generate() for _ in range(100)]

            cracked_lcg = LCG.crack_truncated(outputs, to_predict, multiplier=ref_lcg.a, increment=ref_lcg.c, modulus=ref_lcg.m, trunc_amount=trunc_amount)

            accuracy = sum([ref_lcg.generate() == cracked_lcg.generate() for _ in range(1000)]) / 1000
            self.assertGreater(accuracy, 0.9)



    def test_correctness(self):
        for _ in range(100):
            seed = Bytes.random(16).int()
            a = Bytes.random(2).int()
            m = Bytes.random(12).int()
            c = Bytes.random(2).int()

            lcg     = LCG(X=seed, a=a, c=c, m=m)
            ref_lcg = wiki_lcg(m, a, c, seed).__next__

            self.assertEqual([lcg.generate() for _ in range(10000)], [ref_lcg() for _ in range(10000)])
