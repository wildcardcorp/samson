from samson.block_ciphers.serpent import Serpent
from samson.utilities.bytes import Bytes
import unittest

# http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
class SerpentTestCase(unittest.TestCase):
    # Ensures the cipher always outputs its block size
    def test_zfill(self):
        cipher_obj = Serpent(Bytes(0x8000000000000000).zfill(16))
        plaintext = Bytes(b'').zfill(16)
        ciphertext1 = cipher_obj.encrypt(plaintext)
        ciphertext2 = cipher_obj.decrypt(plaintext)

        self.assertEqual(cipher_obj.decrypt(ciphertext1), plaintext)
        self.assertEqual(cipher_obj.encrypt(ciphertext2), plaintext)



    def _run_test(self, key, plaintext, expected_ciphertext, iter_100):
        serpent = Serpent(key)
        ciphertext = serpent.encrypt(plaintext)
        self.assertEqual(ciphertext, Bytes(expected_ciphertext))
        self.assertEqual(serpent.decrypt(ciphertext), Bytes(plaintext).zfill(16))

        # for _ in range(99):
        #     ciphertext = serpent.encrypt(ciphertext)

        # self.assertEqual(ciphertext, Bytes(iter_100))


    def test_serp_256_0(self):
        key = 0x8000000000000000000000000000000000000000000000000000000000000000
        plaintext = 0x00000000000000000000000000000000
        expected_ciphertext = 0xA223AA1288463C0E2BE38EBD825616C0
        iter_100 = 0x739E0148971FD975B585EAFDBD659E2C
        self._run_test(key, plaintext, expected_ciphertext, iter_100)



    def test_serp_256_1(self):
        key = 0x4000000000000000000000000000000000000000000000000000000000000000
        plaintext = 0x00000000000000000000000000000000
        expected_ciphertext = 0xEAE1D405570174DF7DF2F9966D509159
        iter_100 = 0xDF58B1EBBD9DDCC116F56C6D980A7645
        self._run_test(key, plaintext, expected_ciphertext, iter_100)



    def test_serp_256_2(self):
        key = 0x2000000000000000000000000000000000000000000000000000000000000000
        plaintext = 0x00000000000000000000000000000000
        expected_ciphertext = 0x65F37684471E921DC8A30F45B43C4499
        iter_100 = 0x2E88497FC401DE30A8CFF71B7766545E
        self._run_test(key, plaintext, expected_ciphertext, iter_100)



    def test_serp_256_3(self):
        key = 0x1000000000000000000000000000000000000000000000000000000000000000
        plaintext = 0x00000000000000000000000000000000
        expected_ciphertext = 0x0EE036D0BC32B89C1CEF987F5229E4A9
        iter_100 = 0xF26638B54D01CD36DA7C7A3D9F8B74A3
        self._run_test(key, plaintext, expected_ciphertext, iter_100)



    def test_serp_256_12(self):
        key = Bytes(0x0008000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext = 0x00000000000000000000000000000000
        expected_ciphertext = 0x97905460E140685960B561204ABC09A9
        iter_100 = 0x6F978E0C2F05A0CC970BB146836267EE
        self._run_test(key, plaintext, expected_ciphertext, iter_100)




    def test_serp_256_13(self):
        key = Bytes(0x0004000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext = 0x00000000000000000000000000000000
        expected_ciphertext = 0xB893B8766A12AAAD7691565C46651623
        iter_100 = 0xE7B681E8871FD05FEAE5FB64DA891EA2
        self._run_test(key, plaintext, expected_ciphertext, iter_100)




    def test_serp_256_222(self):
        key = Bytes(0xDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE).zfill(32)
        plaintext = 0xDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE
        expected_ciphertext = 0x8DDC2ED210A96A8319980EF9FC179216
        iter_100 = 0x684E9C8F3201936D45E8AB94765D76D4
        self._run_test(key, plaintext, expected_ciphertext, iter_100)




    def test_serp_256_223(self):
        key = Bytes(0xDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDF).zfill(32)
        plaintext = 0xDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDF
        expected_ciphertext = 0x9C79BAF04FC371244B61D7EC0445643C
        iter_100 = 0xE85AAFBADFF86748F78D75B748A187AA
        self._run_test(key, plaintext, expected_ciphertext, iter_100)
