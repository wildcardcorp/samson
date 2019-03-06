from samson.block_ciphers.twofish import Twofish
from samson.utilities.bytes import Bytes
import unittest

# https://www.schneier.com/academic/paperfiles/paper-twofish-paper.pdf
class TwofishTestCase(unittest.TestCase):
    # Ensures the cipher always outputs its block size
    def test_zfill(self):
        cipher_obj = Twofish(Bytes(0x8000000000000000).zfill(16))
        plaintext = Bytes(b'').zfill(16)
        ciphertext1 = cipher_obj.encrypt(plaintext)
        ciphertext2 = cipher_obj.decrypt(plaintext)#[::-1]

        #ciphertext2 = Bytes(b''.join(ciphertext2.chunk(4)[::-1]))

        self.assertEqual(cipher_obj.decrypt(ciphertext1), plaintext)
        self.assertEqual(cipher_obj.encrypt(ciphertext2), plaintext)



    def _run_test(self, key, plaintext, expected_ciphertext):
        twofish = Twofish(key)
        ciphertext = twofish.encrypt(plaintext)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(twofish.decrypt(ciphertext), plaintext)


    def test_vec0(self):
        key =                   Bytes(0x00000000000000000000000000000000).zfill(16)
        plaintext =             Bytes(0x00000000000000000000000000000000, 'little').zfill(16)#[::-1]
        expected_ciphertext =   Bytes(0x9F589F5CF6122C32B6BFEC2F2AE8C35A).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec1(self):
        key =                   Bytes(0x0123456789ABCDEFFEDCBA98765432100011223344556677).zfill(24)
        plaintext =             Bytes(0x00000000000000000000000000000000, 'little').zfill(16)[::-1]
        expected_ciphertext =   Bytes(0xCFD1D2E5A9BE9CDF501F13B892BD2248).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec2(self):
        key =                   Bytes(0x0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF).zfill(32)
        plaintext =             Bytes(0x00000000000000000000000000000000, 'little').zfill(16)[::-1]
        expected_ciphertext =   Bytes(0x37527BE0052334B89F0CFCCAE87CFA20).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec3(self):
        key =                   Bytes(0xD43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F).zfill(32)
        plaintext =             Bytes(0x90AFE91BB288544F2C32DC239B2635E6, 'little').zfill(16)#[::-1]
        expected_ciphertext =   Bytes(0x6CB4561C40BF0A9705931CB6D408E7FA).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext)
