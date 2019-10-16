from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael
from samson.macs.cmac import CMAC
import unittest

PT1 = Bytes(b'')
PT2 = Bytes(0x6BC1BEE22E409F96E93D7E117393172A)
PT3 = Bytes(0x6BC1BEE22E409F96E93D7E117393172AAE2D8A57)
PT4 = Bytes(0x6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710)

class CMACTestCase(unittest.TestCase):
    def _run_test(self, key, message, expected_tag):
        cmac = CMAC(Rijndael(key))
        tag = cmac.generate(message)
        self.assertEqual(tag, expected_tag)


    def _run_128_test(self, message, expected_tag):
        key = Bytes(0x2B7E151628AED2A6ABF7158809CF4F3C)
        self._run_test(key, message, expected_tag)


    def _run_192_test(self, message, expected_tag):
        key = Bytes(0x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B)
        self._run_test(key, message, expected_tag)


    def _run_256_test(self, message, expected_tag):
        key = Bytes(0x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4)
        self._run_test(key, message, expected_tag)




    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
    def test_vec0(self):
        msg          = PT1
        expected_tag = Bytes(0xBB1D6929E95937287FA37D129B756746)

        self._run_128_test(msg, expected_tag)


    def test_vec1(self):
        msg          = PT2
        expected_tag = Bytes(0x070A16B46B4D4144F79BDD9DD04A287C)

        self._run_128_test(msg, expected_tag)


    def test_vec2(self):
        msg          = PT3
        expected_tag = Bytes(0x7D85449EA6EA19C823A7BF78837DFADE)

        self._run_128_test(msg, expected_tag)


    def test_vec3(self):
        msg          = PT4
        expected_tag = Bytes(0x51F0BEBF7E3B9D92FC49741779363CFE)

        self._run_128_test(msg, expected_tag)


    def test_vec4(self):
        msg          = PT1
        expected_tag = Bytes(0xD17DDF46ADAACDE531CAC483DE7A9367)

        self._run_192_test(msg, expected_tag)


    def test_vec5(self):
        msg          = PT2
        expected_tag = Bytes(0x9E99A7BF31E710900662F65E617C5184)

        self._run_192_test(msg, expected_tag)


    def test_vec6(self):
        msg          = PT3
        expected_tag = Bytes(0x3D75C194ED96070444A9FA7EC740ECF8)

        self._run_192_test(msg, expected_tag)


    def test_vec7(self):
        msg          = PT4
        expected_tag = Bytes(0xA1D5DF0EED790F794D77589659F39A11)

        self._run_192_test(msg, expected_tag)


    def test_vec8(self):
        msg          = PT1
        expected_tag = Bytes(0x028962F61B7BF89EFC6B551F4667D983)

        self._run_256_test(msg, expected_tag)


    def test_vec9(self):
        msg          = PT2
        expected_tag = Bytes(0x28A7023F452E8F82BD4BF28D8C37C35C)

        self._run_256_test(msg, expected_tag)


    def test_vec10(self):
        msg          = PT3
        expected_tag = Bytes(0x156727DC0878944A023C1FE03BAD6D93)

        self._run_256_test(msg, expected_tag)


    def test_vec11(self):
        msg          = PT4
        expected_tag = Bytes(0xE1992190549F6ED5696A2C056C315410)

        self._run_256_test(msg, expected_tag)
