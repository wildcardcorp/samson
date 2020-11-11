from samson.hashes.md2 import MD2
import unittest

# https://tools.ietf.org/html/rfc1319#appendix-A.5
class MD2TestCase(unittest.TestCase):
    def _run_test(self, message, test_vector):
        md2 = MD2()
        self.assertEqual(md2.hash(message).hex(), test_vector)


    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/md4/Md4-128.unverified.test-vectors
    def test_vec0(self):
        self._run_test(b'', b'8350e5a3e24c153df2275c9f80692773')



    def test_vec1(self):
        self._run_test(b'a', b'32ec01ec4a6dac72c0ab96fb34c0b5d1')



    def test_vec2(self):
        self._run_test(b'abc', b'da853b0d3f88d99b30283a69e6ded6bb')



    def test_vec3(self):
        self._run_test(b'message digest', b'ab4f496bfb2a530b219ff33031fe06b0')



    def test_vec4(self):
        self._run_test(b'abcdefghijklmnopqrstuvwxyz', b'4e8ddff3650292ab5a4108c3aa47940b')



    def test_vec5(self):
        self._run_test(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', b'da33def2a42df13975352846c30338cd')



    def test_vec6(self):
        self._run_test(b'1234567890'*8, b'd5976f79d83d3a0dc9806c3c66f3efd8')
