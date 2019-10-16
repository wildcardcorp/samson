from samson.block_ciphers.modes.ofb import OFB
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import unittest

# https://svn.python.org/projects/external/openssl-1.0.2d/test/evptests.txt
class OFBTestCase(unittest.TestCase):
    def _run_test(self, key, iv, plaintext, expected_ciphertext):
        rij = Rijndael(key)
        ofb = OFB(rij, iv)
        ciphertext = ofb.encrypt(plaintext)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(ofb.decrypt(ciphertext), plaintext)



    def test_vec0(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A).zfill(16)
        expected_ciphertext = Bytes(0x3B3FD92EB72DAD20333449F8E83CFB4A).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec1(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0x50FE67CC996D32B6DA0937E99BAFEC60).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51).zfill(16)
        expected_ciphertext = Bytes(0x7789508D16918F03F53C52DAC54ED825).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec2(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0xD9A4DADA0892239F6B8B3D7680E15674).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF).zfill(16)
        expected_ciphertext = Bytes(0x9740051E9C5FECF64344F7A82260EDCC).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec3(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0xA78819583F0308E7A6BF36B1386ABF23).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710).zfill(16)
        expected_ciphertext = Bytes(0x304C6528F659C77866A510D9C1D6AE5E).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec4(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A).zfill(16)
        expected_ciphertext = Bytes(0xCDC80D6FDDF18CAB34C25909C99A4174).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec5(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0xA609B38DF3B1133DDDFF2718BA09565E).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51).zfill(16)
        expected_ciphertext = Bytes(0xFCC28B8D4C63837C09E81700C1100401).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec6(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0x52EF01DA52602FE0975F78AC84BF8A50).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF).zfill(16)
        expected_ciphertext = Bytes(0x8D9A9AEAC0F6596F559C6D4DAF59A5F2).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec7(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0xBD5286AC63AABD7EB067AC54B553F71D).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710).zfill(16)
        expected_ciphertext = Bytes(0x6D9F200857CA6C3E9CAC524BD9ACC92A).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec8(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A).zfill(16)
        expected_ciphertext = Bytes(0xDC7E84BFDA79164B7ECD8486985D3860).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec9(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0xB7BF3A5DF43989DD97F0FA97EBCE2F4A).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51).zfill(16)
        expected_ciphertext = Bytes(0x4FEBDC6740D20B3AC88F6AD82A4FB08D).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec10(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0xE1C656305ED1A7A6563805746FE03EDC).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF).zfill(16)
        expected_ciphertext = Bytes(0x71AB47A086E86EEDF39D1C5BBA97C408).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec11(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0x41635BE625B48AFC1666DD42A09D96E7).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710).zfill(16)
        expected_ciphertext = Bytes(0x0126141D67F37BE8538F5A8BE740E484).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)
