from samson.macs.pmac import PMAC
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import unittest

# https://github.com/miscreant/miscreant.py/blob/master/vectors/aes_pmac.tjson
class PMACTestCase(unittest.TestCase):
    def _run_test(self, key, plaintext, expected_tag):
        rij  = Rijndael(key)
        pmac = PMAC(rij)
        tag  = pmac.generate(plaintext)

        self.assertEqual(tag, expected_tag)


    def test_vec0(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        plaintext    = Bytes(b'')
        expected_tag = Bytes(0x4399572cd6ea5341b8d35876a7098af7)

        self._run_test(key, plaintext, expected_tag)


    def test_vec1(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        plaintext    = Bytes(0x000102).zfill(3)
        expected_tag = Bytes(0x256ba5193c1b991b4df0c51f388a9e27)

        self._run_test(key, plaintext, expected_tag)


    def test_vec2(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        expected_tag = Bytes(0xebbd822fa458daf6dfdad7c27da76338)

        self._run_test(key, plaintext, expected_tag)


    def test_vec3(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f10111213).zfill(20)
        expected_tag = Bytes(0x0412ca150bbf79058d8c75a58c993f55)

        self._run_test(key, plaintext, expected_tag)


    def test_vec4(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        expected_tag = Bytes(0xe97ac04e9e5e3399ce5355cd7407bc75)

        self._run_test(key, plaintext, expected_tag)


    def test_vec5(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021).zfill(34)
        expected_tag = Bytes(0x5cba7d5eb24f7c86ccc54604e53d5512)

        self._run_test(key, plaintext, expected_tag)


    def test_vec6(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        plaintext    = Bytes(0x0).zfill(1000)
        expected_tag = Bytes(0xc2c9fa1d9985f6f0d2aff915a0e8d910)

        self._run_test(key, plaintext, expected_tag)


    def test_vec7(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        plaintext    = Bytes(b'')
        expected_tag = Bytes(0xe620f52fe75bbe87ab758c0624943d8b)

        self._run_test(key, plaintext, expected_tag)


    def test_vec8(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        plaintext    = Bytes(0x000102).zfill(3)
        expected_tag = Bytes(0xffe124cc152cfb2bf1ef5409333c1c9a)

        self._run_test(key, plaintext, expected_tag)


    def test_vec9(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f).zfill(16)
        expected_tag = Bytes(0x853fdbf3f91dcd36380d698a64770bab)

        self._run_test(key, plaintext, expected_tag)


    def test_vec10(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f10111213).zfill(20)
        expected_tag = Bytes(0x7711395fbe9dec19861aeb96e052cd1b)

        self._run_test(key, plaintext, expected_tag)


    def test_vec11(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        expected_tag = Bytes(0x08fa25c28678c84d383130653e77f4c0)

        self._run_test(key, plaintext, expected_tag)


    def test_vec12(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        plaintext    = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021).zfill(34)
        expected_tag = Bytes(0xedd8a05f4b66761f9eee4feb4ed0c3a1)

        self._run_test(key, plaintext, expected_tag)


    def test_vec13(self):
        key          = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        plaintext    = Bytes(0x0).zfill(1000)
        expected_tag = Bytes(0x69aa77f231eb0cdff960f5561d29a96e)

        self._run_test(key, plaintext, expected_tag)
