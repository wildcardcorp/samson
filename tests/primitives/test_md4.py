from samson.hashes.md4 import MD4
import codecs
import unittest


class MD4TestCase(unittest.TestCase):
    def _run_test(self, message, test_vector):
        md4 = MD4()
        self.assertEqual(md4.hash(message), test_vector)


    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/md4/Md4-128.unverified.test-vectors
    def test_vec0(self):
        self._run_test(b'', codecs.decode(b'31D6CFE0D16AE931B73C59D7E0C089C0', 'hex_codec'))



    def test_vec1(self):
        self._run_test(b'a', codecs.decode(b'BDE52CB31DE33E46245E05FBDBD6FB24', 'hex_codec'))



    def test_vec2(self):
        self._run_test(b'abc', codecs.decode(b'A448017AAF21D8525FC10AE87AA6729D', 'hex_codec'))



    def test_vec3(self):
        self._run_test(b'message digest', codecs.decode(b'D9130A8164549FE818874806E1C7014B', 'hex_codec'))



    def test_vec4(self):
        self._run_test(b'abcdefghijklmnopqrstuvwxyz', codecs.decode(b'D79E1C308AA5BBCDEEA8ED63DF412DA9', 'hex_codec'))



    def test_vec5(self):
        self._run_test(b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', codecs.decode(b'4691A9EC81B1A6BD1AB8557240B245C5', 'hex_codec'))



    def test_vec6(self):
        self._run_test(b'1234567890' * 8, codecs.decode(b'E33B4DDC9C38F2199C3E7B164FCC0536', 'hex_codec'))



    def test_vec7(self):
        self._run_test(b'a' * int(1e6), codecs.decode(b'BBCE80CC6BB65E5C6745E30D4EECA9A4', 'hex_codec'))
