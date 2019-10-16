from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ecb import ECB
from samson.utilities.bytes import Bytes
import unittest


# https://svn.python.org/projects/external/openssl-1.0.2d/test/evptests.txt
class ECBTestCase(unittest.TestCase):
    def _run_test(self, key, plaintext, expected_ciphertext):
        rij = Rijndael(key)
        ecb = ECB(rij)
        ciphertext  = ecb.encrypt(plaintext, pad=False)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(ecb.decrypt(ciphertext, unpad=False), plaintext)



    def test_vec0(self):
        key                 = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C).zfill(16)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710).zfill(64)
        expected_ciphertext = Bytes(0x3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4).zfill(64)

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec1(self):
        key                 = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B).zfill(24)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710).zfill(64)
        expected_ciphertext = Bytes(0xBD334F1D6E45F25FF712A214571FA5CC974104846D0AD3AD7734ECB3ECEE4EEFEF7AFD2270E2E60ADCE0BA2FACE6444E9A4B41BA738D6C72FB16691603C18E0E).zfill(64)

        self._run_test(key, plaintext, expected_ciphertext)


    def test_vec2(self):
        key                 = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4).zfill(32)
        plaintext           = Bytes(0x6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710).zfill(64)
        expected_ciphertext = Bytes(0xF3EED1BDB5D2A03C064B5A7E3DB181F8591CCB10D410ED26DC5BA74A31362870B6ED21B99CA6F4F9F153E7B1BEAFED1D23304B7A39F9F3FF067D8D8F9E24ECC7).zfill(64)

        self._run_test(key, plaintext, expected_ciphertext)
