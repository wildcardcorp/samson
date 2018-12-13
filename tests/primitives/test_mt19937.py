from samson.prngs.mt19937 import MT19937
import unittest
import random

class MT19937TestCase(unittest.TestCase):
    def test_vec0(self):
        for _ in range(50):
            observed_outputs = [random.getrandbits(32) for _ in range(624)]
            mt = MT19937.crack(observed_outputs)

            self.assertEqual([mt.generate() for _ in range(10000)], [random.getrandbits(32) for _ in range(10000)])
