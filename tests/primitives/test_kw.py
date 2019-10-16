from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.kw import KW
from samson.utilities.bytes import Bytes
import unittest

class KWTestCase(unittest.TestCase):
    def __run_test(self, kek, cek, expected_wrapping, iv=KW.RFC3394_IV, pad=False):
        rij = Rijndael(kek)
        kw  = KW(rij, iv=iv)
        wrapped_key = kw.encrypt(cek, pad=pad)

        self.assertEqual(wrapped_key, expected_wrapping)
        self.assertEqual(kw.decrypt(wrapped_key, unpad=pad), cek)


    # https://tools.ietf.org/html/rfc3394.html#section-4.1
    def test_vec0(self):
        kek               = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        cek               = Bytes(0x00112233445566778899AABBCCDDEEFF).zfill(16)
        expected_wrapping = Bytes(0x1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5)

        self.__run_test(kek, cek, expected_wrapping)


    def test_vec1(self):
        kek               = Bytes(0x000102030405060708090A0B0C0D0E0F1011121314151617).zfill(24)
        cek               = Bytes(0x00112233445566778899AABBCCDDEEFF).zfill(16)
        expected_wrapping = Bytes(0x96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D)

        self.__run_test(kek, cek, expected_wrapping)


    def test_vec2(self):
        kek               = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F).zfill(32)
        cek               = Bytes(0x00112233445566778899AABBCCDDEEFF).zfill(16)
        expected_wrapping = Bytes(0x64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7)

        self.__run_test(kek, cek, expected_wrapping)


    def test_vec3(self):
        kek               = Bytes(0x000102030405060708090A0B0C0D0E0F1011121314151617).zfill(24)
        cek               = Bytes(0x00112233445566778899AABBCCDDEEFF0001020304050607).zfill(24)
        expected_wrapping = Bytes(0x031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2)

        self.__run_test(kek, cek, expected_wrapping)


    def test_vec4(self):
        kek               = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F).zfill(32)
        cek               = Bytes(0x00112233445566778899AABBCCDDEEFF0001020304050607).zfill(24)
        expected_wrapping = Bytes(0xA8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1)

        self.__run_test(kek, cek, expected_wrapping)


    def test_vec5(self):
        kek               = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F).zfill(32)
        cek               = Bytes(0x00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F).zfill(32)
        expected_wrapping = Bytes(0x28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21)

        self.__run_test(kek, cek, expected_wrapping)


    # https://tools.ietf.org/html/rfc5649.html#section-6
    def test_vec6(self):
        kek               = Bytes(0x5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8)
        cek               = Bytes(0xc37b7e6492584340bed12207808941155068f738)
        expected_wrapping = Bytes(0x138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a)

        self.__run_test(kek, cek, expected_wrapping, iv=KW.RFC5649_IV, pad=True)


    def test_vec7(self):
        kek               = Bytes(0x5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8)
        cek               = Bytes(0x466f7250617369)
        expected_wrapping = Bytes(0xafbeb0f07dfbf5419200f2ccb50bb24f)

        self.__run_test(kek, cek, expected_wrapping, iv=KW.RFC5649_IV, pad=True)
