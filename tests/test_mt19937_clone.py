#!/usr/bin/python3
from samson.attacks.mt19937_clone_attack import MT19937CloneAttack
from samson.primitives.mt19937 import MT19937
import unittest


class MT19937CloneAttackTestCase(unittest.TestCase):
    def setUp(self):
        self.rand = MT19937(1024)


    def test_clone_attack(self):
        attack = MT19937CloneAttack(self)
        cloned = attack.execute()
        self.assertEqual(self.rand.randint(), cloned.randint())


    def request(self):
        return self.rand.randint()