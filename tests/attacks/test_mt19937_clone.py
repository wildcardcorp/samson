#!/usr/bin/python3
from samson.prngs.mt19937 import MT19937
import unittest


class MT19937CloneAttackTestCase(unittest.TestCase):
    def setUp(self):
        self.rand = MT19937(1024)


    def test_clone_attack(self):
        cloned = MT19937.crack([self.rand.generate() for i in range(624)])
        self.assertEqual(self.rand.generate(), cloned.generate())