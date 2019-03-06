from samson.block_ciphers.rc5 import RC5
from samson.utilities.bytes import Bytes
import unittest


class RC5TestCase(unittest.TestCase):
    # Ensures the cipher always outputs its block size
    def test_zfill(self):
        cipher_obj = RC5(key=Bytes(0x8000000000000000).zfill(8), num_rounds=16, block_size=64)
        plaintext = Bytes(b'').zfill(8)
        ciphertext1 = cipher_obj.encrypt(plaintext)
        ciphertext2 = cipher_obj.decrypt(plaintext)

        self.assertEqual(cipher_obj.decrypt(ciphertext1), plaintext)
        self.assertEqual(cipher_obj.encrypt(ciphertext2), plaintext)



    def _run_test(self, key, plaintext, num_rounds, block_size, test_vector, iterations=1):
        rc5 = RC5(key=key, num_rounds=num_rounds, block_size=block_size)
        ct = rc5.encrypt(plaintext)

        self.assertEqual(rc5.decrypt(ct), plaintext)
        self.assertEqual(ct, test_vector)




    def test_vec1(self):
        key         = Bytes.wrap(0x0001020304050607).zfill(8)
        plaintext   = Bytes(0x00010203).zfill(4)[::-1]
        test_vector = Bytes.wrap(0x23A8D72E).zfill(4)

        self._run_test(key=key, plaintext=plaintext, test_vector=test_vector, block_size=32, num_rounds=16)



    def test_vec2(self):
        key = Bytes.wrap(0x000102030405060708090A0B0C0D0E0F, 'big').zfill(16)
        plaintext = int.to_bytes(0x0001020304050607, 8, 'little')
        test_vector = Bytes.wrap(0x2A0EDC0E9431FF73).zfill(8)

        self._run_test(key=key, plaintext=plaintext, test_vector=test_vector, block_size=64, num_rounds=20)



    def test_vec3(self):
        key = Bytes.wrap(0x000102030405060708090A0B0C0D0E0F1011121314151617, 'big').zfill(24)
        plaintext = int.to_bytes(0x000102030405060708090A0B0C0D0E0F, 16, 'little')
        test_vector = Bytes.wrap(0xA46772820EDBCE0235ABEA32AE7178DA).zfill(16)

        self._run_test(key=key, plaintext=plaintext, test_vector=test_vector, block_size=128, num_rounds=24)
