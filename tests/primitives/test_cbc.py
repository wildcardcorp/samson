from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.cbc import CBC
from samson.utilities.bytes import Bytes
import unittest

# https://svn.python.org/projects/external/openssl-1.0.2d/test/evptests.txt
class CBCTestCase(unittest.TestCase):
    def _run_test(self, key, iv, plaintext, expected_ciphertext):
        rij = Rijndael(key)
        cbc = CBC(rij, iv=iv)
        ciphertext = cbc.encrypt(plaintext, pad=False)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(cbc.decrypt(ciphertext, unpad=False), plaintext)


    def test_vec0(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A)
        expected_ciphertext = Bytes(0x7649ABAC8119B246CEE98E9B12E9197D)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec1(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C)
        iv                  = Bytes(0x7649ABAC8119B246CEE98E9B12E9197D).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51)
        expected_ciphertext = Bytes(0x5086CB9B507219EE95DB113A917678B2)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec2(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C)
        iv                  = Bytes(0x5086CB9B507219EE95DB113A917678B2).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF)
        expected_ciphertext = Bytes(0x73BED6B8E3C1743B7116E69E22229516)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec3(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C)
        iv                  = Bytes(0x73BED6B8E3C1743B7116E69E22229516).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710)
        expected_ciphertext = Bytes(0x3FF1CAA1681FAC09120ECA307586E1A7)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec4(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A)
        expected_ciphertext = Bytes(0x4F021DB243BC633D7178183A9FA071E8)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec5(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B)
        iv                  = Bytes(0x4F021DB243BC633D7178183A9FA071E8).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51)
        expected_ciphertext = Bytes(0xB4D9ADA9AD7DEDF4E5E738763F69145A)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec6(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B)
        iv                  = Bytes(0xB4D9ADA9AD7DEDF4E5E738763F69145A).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF)
        expected_ciphertext = Bytes(0x571B242012FB7AE07FA9BAAC3DF102E0)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec7(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B)
        iv                  = Bytes(0x571B242012FB7AE07FA9BAAC3DF102E0).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710)
        expected_ciphertext = Bytes(0x08B0E27988598881D920A9E64F5615CD)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec8(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A)
        expected_ciphertext = Bytes(0xF58C4C04D6E5F1BA779EABFB5F7BFBD6)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec9(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4)
        iv                  = Bytes(0xF58C4C04D6E5F1BA779EABFB5F7BFBD6).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51)
        expected_ciphertext = Bytes(0x9CFC4E967EDB808D679F777BC6702C7D)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec10(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4)
        iv                  = Bytes(0x9CFC4E967EDB808D679F777BC6702C7D).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF)
        expected_ciphertext = Bytes(0x39F23369A9D9BACFA530E26304231461)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec11(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4)
        iv                  = Bytes(0x39F23369A9D9BACFA530E26304231461).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710)
        expected_ciphertext = Bytes(0xB2EB05E2C39BE9FCDA6C19078C6A9D1B)

        self._run_test(key, iv, plaintext, expected_ciphertext)
