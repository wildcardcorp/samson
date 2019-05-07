from samson.public_key.elgamal import ElGamal
from samson.utilities.bytes import Bytes
import unittest

# https://github.com/Legrandin/pycrypto/blob/7834db2809024536cdfd7fef0b5657dd390bd780/lib/Crypto/SelfTest/PublicKey/test_ElGamal.py
class ElGamalTestCase(unittest.TestCase):
    def _run_test(self, g, p, key, pub, k, plaintext, expected_ciphertext):
        elgamal = ElGamal(g, p, key)
        ciphertext = elgamal.encrypt(plaintext, k)

        self.assertEqual(elgamal.pub, pub)
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(elgamal.decrypt(ciphertext).int(), plaintext)


    def test_vec0(self):
        p         = 0xBA4CAEAAED8CBE952AFD2126C63EB3B345D65C2A0A73D2A3AD4138B6D09BD933
        g         = 0x5
        key       = 0x1D391BA2EE3C37FE1BA175A69B2C73A11238AD77675932
        pub       = 0x60D063600ECED7C7C55146020E7A31C4476E9793BEAED420FEC9E77604CAE4EF
        k         = 0xF5893C5BAB4131264066F57AB3D8AD89E391A0B68A68A1
        plaintext = 0x48656C6C6F207468657265
        expected_ciphertext = (0x32BFD5F487966CEA9E9356715788C491EC515E4ED48B58F0F00971E93AAA5EC7, 0x7BE8FBFF317C93E82FCEF9BD515284BA506603FEA25D01C0CB874A31F315EE68)

        self._run_test(g, p, key, pub, k, plaintext, expected_ciphertext)


    def test_vec1(self):
        p         = 0xF1B18AE9F7B4E08FDA9A04832F4E919D89462FD31BF12F92791A93519F75076D6CE3942689CDFF2F344CAFF0F82D01864F69F3AECF566C774CBACF728B81A227
        g         = 0x7
        key       = 0x14E60B1BDFD33436C0DA8A22FDC14A2CCDBBED0627CE68
        pub       = 0x688628C676E4F05D630E1BE39D0066178CA7AA83836B645DE5ADD359B4825A12B02EF4252E4E6FA9BEC1DB0BE90F6D7C8629CABB6E531F472B2664868156E20C
        k         = 0x38DBF14E1F319BDA9BAB33EEEADCAF6B2EA5250577ACE7
        plaintext = 0x48656C6C6F207468657265
        expected_ciphertext = (0x290F8530C2CC312EC46178724F196F308AD4C523CEABB001FACB0506BFED676083FE0F27AC688B5C749AB3CB8A80CD6F7094DBA421FB19442F5A413E06A9772B, 0x1D69AAAD1DC50493FB1B8E8721D621D683F3BF1321BE21BC4A43E11B40C9D4D9C80DE3AAC2AB60D31782B16B61112E68220889D53C4C3136EE6F6CE61F8A23A0)

        self._run_test(g, p, key, pub, k, plaintext, expected_ciphertext)



    def test_gauntlet(self):
        for _ in range(100):
            elgamal = ElGamal()
            plaintext = Bytes.random(8)
            ciphertext = elgamal.encrypt(plaintext)
            self.assertEqual(plaintext, elgamal.decrypt(ciphertext).zfill(8))
