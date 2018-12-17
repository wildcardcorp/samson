from samson.public_key.paillier import Paillier
import unittest

class PaillierTestCase(unittest.TestCase):
    def test_paillier(self):
        pail = Paillier()

        plaintext = b'my secret message'
        ciphertext = pail.encrypt(plaintext)

        self.assertEqual(pail.decrypt(ciphertext), plaintext)
