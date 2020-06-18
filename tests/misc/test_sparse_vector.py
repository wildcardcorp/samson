from samson.utilities.bytes import Bytes
from samson.math.sparse_vector import SparseVector
import unittest

class SparseVectorTestCase(unittest.TestCase):

    def test_gauntlet(self):
        """
        Need to make sure SparseVector behaves exactly the same as a list.
        """
        for trial in range(100000):
            num    = Bytes.random(1).int()
            values = [Bytes.random(1).int() % 64 for _ in range(num)]
            vec    = SparseVector(values, 0)

            assert len(vec) == len(values)

            idx = Bytes.random(1).int()
            assert len(vec[:idx]) == len(values[:idx])
            assert vec[:idx].list() == values[:idx]

            assert len(vec[idx:]) == len(values[idx:])
            assert vec[idx:].list() == values[idx:]

            assert (vec[:idx] + vec[idx:]).list() == values
            assert (vec[:idx] + values[idx:]).list() == values

            if len(values):
                idx_trunc = idx % len(values)
                assert vec[idx_trunc] == values[idx_trunc]
