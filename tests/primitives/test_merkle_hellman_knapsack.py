from samson.public_key.merkle_hellman_knapsack import MerkleHellmanKnapsack
from samson.utilities.bytes import Bytes
import unittest

class MerkleHellmanKnapsackTestCase(unittest.TestCase):
    def test_mhk(self):
        knap = MerkleHellmanKnapsack()
        plaintext = Bytes.random(2)
        ciphertext = knap.encrypt(plaintext)

        self.assertEqual(knap.decrypt(ciphertext), plaintext)
        self.assertEqual(MerkleHellmanKnapsack.recover_plaintext(ciphertext[0], knap.pub), Bytes(plaintext[0]))
