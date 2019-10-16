from samson.block_ciphers.modes.cfb import CFB
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import unittest

# https://svn.python.org/projects/external/openssl-1.0.2d/test/evptests.txt
class CFBTestCase(unittest.TestCase):
    def _run_test(self, key, iv, plaintext, expected_ciphertext):
        rij = Rijndael(key)
        cfb = CFB(rij, iv)
        ciphertext = cfb.encrypt(plaintext)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(cfb.decrypt(ciphertext), plaintext)



    def test_vec0(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A).zfill(16)
        expected_ciphertext = Bytes(0x3B3FD92EB72DAD20333449F8E83CFB4A).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec1(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0x3B3FD92EB72DAD20333449F8E83CFB4A).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51).zfill(16)
        expected_ciphertext = Bytes(0xC8A64537A0B3A93FCDE3CDAD9F1CE58B).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec2(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0xC8A64537A0B3A93FCDE3CDAD9F1CE58B).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF).zfill(16)
        expected_ciphertext = Bytes(0x26751F67A3CBB140B1808CF187A4F4DF).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)



    def test_vec3(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        iv                  = Bytes(0x26751F67A3CBB140B1808CF187A4F4DF).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710).zfill(16)
        expected_ciphertext = Bytes(0xC04B05357C5D1C0EEAC4C66F9FF7F2E6).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec4(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A).zfill(16)
        expected_ciphertext = Bytes(0xCDC80D6FDDF18CAB34C25909C99A4174).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec5(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0xCDC80D6FDDF18CAB34C25909C99A4174).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51).zfill(16)
        expected_ciphertext = Bytes(0x67CE7F7F81173621961A2B70171D3D7A).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec6(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0x67CE7F7F81173621961A2B70171D3D7A).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF).zfill(16)
        expected_ciphertext = Bytes(0x2E1E8A1DD59B88B1C8E60FED1EFAC4C9).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec7(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        iv                  = Bytes(0x2E1E8A1DD59B88B1C8E60FED1EFAC4C9).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710).zfill(16)
        expected_ciphertext = Bytes(0xC05F9F9CA9834FA042AE8FBA584B09FF).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec8(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172A).zfill(16)
        expected_ciphertext = Bytes(0xDC7E84BFDA79164B7ECD8486985D3860).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec9(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0xDC7E84BFDA79164B7ECD8486985D3860).zfill(16)
        plaintext           = Bytes(0xAE2D8A571E03AC9C9EB76FAC45AF8E51).zfill(16)
        expected_ciphertext = Bytes(0x39FFED143B28B1C832113C6331E5407B).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)


    def test_vec10(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0x39FFED143B28B1C832113C6331E5407B).zfill(16)
        plaintext           = Bytes(0x30C81C46A35CE411E5FBC1191A0A52EF).zfill(16)
        expected_ciphertext = Bytes(0xDF10132415E54B92A13ED0A8267AE2F9).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)



    def test_vec11(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        iv                  = Bytes(0xDF10132415E54B92A13ED0A8267AE2F9).zfill(16)
        plaintext           = Bytes(0xF69F2445DF4F9B17AD2B417BE66C3710).zfill(16)
        expected_ciphertext = Bytes(0x75A385741AB9CEF82031623D55B1E471).zfill(16)

        self._run_test(key, iv, plaintext, expected_ciphertext)
