from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.ccm import CCM

import unittest

# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
TEST_VECTORS = [
    [0x404142434445464748494a4b4c4d4e4f, 0x10111213141516, 0x0001020304050607, 4, 0x20212223, 0x7162015b4dac255d],
    [0x404142434445464748494a4b4c4d4e4f, 0x1011121314151617, 0x000102030405060708090a0b0c0d0e0f, 6, 0x202122232425262728292a2b2c2d2e2f, 0xd2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd],
    [0x404142434445464748494a4b4c4d4e4f, 0x101112131415161718191a1b, 0x000102030405060708090a0b0c0d0e0f10111213, 8, 0x202122232425262728292a2b2c2d2e2f3031323334353637, 0xe3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951]
]

class CCMTestCase(unittest.TestCase):
    def test_all_vecs(self):
        for key, nonce, data, size, plaintext, expected_ciphertext in TEST_VECTORS:
            key = Bytes(key)
            nonce = Bytes(nonce)
            data = Bytes(data)
            data = data.zfill(len(data) + 1)
            plaintext = Bytes(plaintext)

            ccm = CCM(Rijndael(key), size)
            ciphertext = ccm.encrypt(nonce, plaintext, data)
            self.assertEqual(ciphertext, Bytes(expected_ciphertext))
            self.assertEqual(ccm.decrypt(nonce, ciphertext, data), plaintext)
