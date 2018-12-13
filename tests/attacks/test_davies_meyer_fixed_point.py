from samson.constructions.davies_meyer_construction import DaviesMeyerConstruction
from samson.block_ciphers.rijndael import Rijndael
import unittest


class DaviesMeyerFixedPointTestCase(unittest.TestCase):
    def test_fixed_point(self):
        message = b'this is 16 bytes'
        dmc = DaviesMeyerConstruction.generate_fixed_point(Rijndael, message, 16)
        self.assertEqual(dmc.hash(message), dmc.hash(message * 1000))
