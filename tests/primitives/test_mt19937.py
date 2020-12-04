from samson.prngs.mt19937 import MT19937
import unittest
import random

class MT19937TestCase(unittest.TestCase):
    def test_vec0(self):
        for _ in range(50):
            observed_outputs = [random.getrandbits(32) for _ in range(624)]
            mt = MT19937.crack(observed_outputs)

            self.assertEqual([mt.generate() for _ in range(10000)], [random.getrandbits(32) for _ in range(10000)])


    def test_reverse_clock(self):
        for _ in range(50):
            mt = MT19937(random.getrandbits(32))

            # Does it work in general?
            self.assertEqual([mt.generate() for _ in range(3)][::-1], [mt.reverse_clock() for _ in range(3)])

            # Does it work over a twist boundary?
            self.assertEqual([mt.reverse_clock() for _ in range(3)][::-1], [mt.generate() for _ in range(3)])

            # Does it work for an entire state?
            self.assertEqual([mt.generate() for _ in range(624)][::-1], [mt.reverse_clock() for _ in range(624)])

            # Does it work for an entire state over a twist boundary?
            self.assertEqual([mt.generate() for _ in range(624*2)][::-1], [mt.reverse_clock() for _ in range(624*2)])
