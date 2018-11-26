from samson.protocols.ecdhe import ECDHE
import unittest

class ECDHETestCase(unittest.TestCase):
    def test_ecdhe(self):
        ecdhe1 = ECDHE()
        ecdhe2 = ECDHE()

        ch1 = ecdhe1.get_challenge()
        ch2 = ecdhe2.get_challenge()

        self.assertEqual(ecdhe1.derive_key(ch2), ecdhe2.derive_key(ch1))