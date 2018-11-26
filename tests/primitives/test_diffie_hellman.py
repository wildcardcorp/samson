from samson.protocols.diffie_hellman import DiffieHellman
import unittest

class DiffieHellmanTestCase(unittest.TestCase):
    def test_dh(self):
        dh1 = DiffieHellman()
        dh2 = DiffieHellman()

        ch1 = dh1.get_challenge()
        ch2 = dh2.get_challenge()

        self.assertEqual(dh1.derive_key(ch2), dh2.derive_key(ch1))