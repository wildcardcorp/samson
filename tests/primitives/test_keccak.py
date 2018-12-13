from samson.hashes.keccak import Keccak
from samson.utilities.bytes import Bytes
import unittest

PARAMS = [
    (1152, 448, 224),
    (1088, 512, 256),
    (832, 768, 384),
    (576, 1024, 512)
]


# https://asecuritysite.com/encryption/s3?m=
class KeccakTestCase(unittest.TestCase):
    def _run_test(self, plaintext, expected_hashes):
        for i, expected_hash in enumerate(expected_hashes):
            keccak = Keccak(*PARAMS[i])
            self.assertEqual(keccak.hash(plaintext), expected_hash)


    def test_vec0(self):
        plaintext = Bytes(b'')
        expected_hashes = [
            Bytes(0xf71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd),
            Bytes(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470),
            Bytes(0x2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff),
            Bytes(0x0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e)
        ]

        self._run_test(plaintext, expected_hashes)


    def test_vec1(self):
        plaintext = Bytes(b'The quick brown fox jumps over the lazy dog')
        expected_hashes = [
            Bytes(0x310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe),
            Bytes(0x4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15),
            Bytes(0x283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3),
            Bytes(0xd135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609)
        ]

        self._run_test(plaintext, expected_hashes)



    def test_vec2(self):
        plaintext = Bytes(b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu')
        expected_hashes = [
            Bytes(0x344298994b1b06873eae2ce739c425c47291a2e24189e01b524f88dc),
            Bytes(0xf519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67),
            Bytes(0xcc063f34685135368b34f7449108f6d10fa727b09d696ec5331771da46a923b6c34dbd1d4f77e595689c1f3800681c28),
            Bytes(0xac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f3f1db7a983dad13d53439ccac0b37e24037e7b95f80f59f37a2f683c4ba4682)
        ]

        self._run_test(plaintext, expected_hashes)



    def test_vec3(self):
        plaintext = Bytes(b'1de75ff2c5ab1a3a9a85324b9a081aab4164e43671066a635470188e28e276b02a9b760ee6d846c5655741aa1dbc3a87e97ee6a377c80c6af34cad932fd6d80f127fed004b32a7fc7832f0f0796d6b6c775543e41d1c15103a4ed99124ada3f71a4ae894e6795d65a8b7308c4ab58e32dcfb5b3e32962b8824142ec4137fb46e84e64000945c30e56bd3fdd366d863a6a7fdb7fdd52acf49c1394fd0d1e385884fa1fb756a17756fe24ab568628d09dec417fb6f1705a15ad7db3f92caa2299d0e7543718f09528eafce63ce5fbabca171fb229e68a1fac7436a10f6e70f5af557edac4e7fa51546472458696ceb16614e957c808759f07741d3b443fcd18f30')
        expected_hashes = [
            Bytes(0xc8331bfd5f41e7465d800dfbcc96fc7d72f546056012cb2bbd0e6281),
            Bytes(0xc05f11ce7a5352413751755671ace5c438275539484eddcd36c8019aa3162d7f),
            Bytes(0x969f058237bde649a5960186d7c440d71d65381251d82abdfcb34564197c134ae6261b5ce9a373faf3ddce8149cdc0c9),
            Bytes(0x01c7cb8613c80d4142b48cf7a160d8c4312977c827cef5e156e2158707fac726f823a062cedc526d3f1490597eaa8a9b85fb8d4579ad183afddb463cdae74d39)
        ]

        self._run_test(plaintext, expected_hashes)
