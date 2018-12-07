from samson.prngs.pcg import PCG
import unittest

# TODO: Test with reference code
class PCGTestCase(unittest.TestCase):
    def test_correctness(self):
        pcg = PCG(seed=0, multiplier=6364136223846793005, increment=0)