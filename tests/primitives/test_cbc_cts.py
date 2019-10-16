from samson.block_ciphers.modes.cbc_cts import CBCCTS
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import unittest

# Test vectors from https://www.ietf.org/rfc/rfc3962.txt
class CBCCTSTestCase(unittest.TestCase):
    def test_gauntlet(self):
        rij = Rijndael(Bytes(0x0).zfill(32))
        cts = CBCCTS(rij, iv=b'\x00' * 16)

        for _ in range(100):
            plaintext = Bytes.random(Bytes.random(1).int() + 17)

            if len(plaintext) < 17:
                plaintext = plaintext.zfill(17)

            ciphertext = cts.encrypt(plaintext)
            self.assertEqual(cts.decrypt(ciphertext), plaintext)


    def _run_test(self, plaintext, expected_ciphertext):
        rij = Rijndael(0x636869636b656e207465726979616b69)
        cts = CBCCTS(rij, iv=b'\x00' * 16)

        ciphertext = cts.encrypt(plaintext)
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(cts.decrypt(ciphertext), plaintext)



    def test_vec0(self):
        plaintext           = Bytes(0x4920776f756c64206c696b652074686520)
        expected_ciphertext = Bytes(0xc6353568f2bf8cb4d8a580362da7ff7f97)
        self._run_test(plaintext, expected_ciphertext)


    def test_vec1(self):
        plaintext           = Bytes(0x4920776f756c64206c696b65207468652047656e6572616c20476175277320)
        expected_ciphertext = Bytes(0xfc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5)
        self._run_test(plaintext, expected_ciphertext)


    def test_vec2(self):
        plaintext           = Bytes(0x4920776f756c64206c696b65207468652047656e6572616c2047617527732043)
        expected_ciphertext = Bytes(0x39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584)
        self._run_test(plaintext, expected_ciphertext)


    def test_vec3(self):
        plaintext           = Bytes(0x4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c)
        expected_ciphertext = Bytes(0x97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5)
        self._run_test(plaintext, expected_ciphertext)


    def test_vec4(self):
        plaintext           = Bytes(0x4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20)
        expected_ciphertext = Bytes(0x97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8)
        self._run_test(plaintext, expected_ciphertext)


    def test_vec5(self):
        plaintext           = Bytes(0x4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e)
        expected_ciphertext = Bytes(0x97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8)
        self._run_test(plaintext, expected_ciphertext)
