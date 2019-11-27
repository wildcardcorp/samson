from samson.block_ciphers.tdes import TDES
from samson.block_ciphers.modes.cbc import CBC
from samson.block_ciphers.modes.ecb import ECB
from samson.utilities.bytes import Bytes
import unittest



class TDESTestCase(unittest.TestCase):
    def _run_cbc_test(self, key, iv, plaintext, expected_ciphertext):
        tdes = TDES(key)
        cbc  = CBC(tdes, iv)
        ciphertext = cbc.encrypt(plaintext, pad=False)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(cbc.decrypt(ciphertext, unpad=False), plaintext)


    def _run_ecb_test(self, key, plaintext, expected_ciphertext):
        tdes = TDES(key)
        ecb  = ECB(tdes)
        ciphertext = ecb.encrypt(plaintext, pad=False)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(ecb.decrypt(ciphertext, unpad=False), plaintext)


    # https://svn.python.org/projects/external/openssl-1.0.2d/test/evptests.txt
    def test_vec0(self):
        key                 = Bytes(0x0123456789abcdeff1e0d3c2b5a49786fedcba9876543210).zfill(24)
        iv                  = Bytes(0xfedcba9876543210).zfill(8)
        plaintext           = Bytes(0x37363534333231204E6F77206973207468652074696D6520666F722000000000).zfill(32)
        expected_ciphertext = Bytes(0x3FE301C962AC01D02213763C1CBD4CDC799657C064ECF5D41C673812CFDE9675).zfill(32)

        self._run_cbc_test(key, iv, plaintext, expected_ciphertext)



    # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-20.pdf
    def test_vec1(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x8000000000000000).zfill(8)
        expected_ciphertext = Bytes(0x95F8A5E5DD31D900).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec2(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x4000000000000000).zfill(8)
        expected_ciphertext = Bytes(0xDD7F121CA5015619).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec3(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x2000000000000000).zfill(8)
        expected_ciphertext = Bytes(0x2E8653104F3834EA).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec4(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x1000000000000000).zfill(8)
        expected_ciphertext = Bytes(0x4BD388FF6CD81D4F).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec5(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x0800000000000000).zfill(8)
        expected_ciphertext = Bytes(0x20B9E767B2FB1456).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec6(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x0400000000000000).zfill(8)
        expected_ciphertext = Bytes(0x55579380D77138EF).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec7(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x0200000000000000).zfill(8)
        expected_ciphertext = Bytes(0x6CC5DEFAAF04512F).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec8(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x0100000000000000).zfill(8)
        expected_ciphertext = Bytes(0x0D9F279BA5D87260).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec9(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x0080000000000000).zfill(8)
        expected_ciphertext = Bytes(0xD9031B0271BD5A0A).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)


    def test_vec10(self):
        key                 = Bytes(0x0101010101010101).stretch(24)
        plaintext           = Bytes(0x0040000000000000).zfill(8)
        expected_ciphertext = Bytes(0x424250B37C3DD951).zfill(8)

        self._run_ecb_test(key, plaintext, expected_ciphertext)
