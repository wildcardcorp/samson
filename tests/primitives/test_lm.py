from samson.hashes.lm import LM
import unittest

class LMTestCase(unittest.TestCase):
    def _run_test(self, plaintext, expected_hash):
        lm = LM()
        self.assertEqual(lm.hash(plaintext).hex().upper(), expected_hash)

    def test_vec0(self):
        self._run_test(b'napier', b'12B9C54F6FE0EC80AAD3B435B51404EE')

    def test_vec1(self):
        self._run_test(b'aaaaaaaaaaaaaa', b'CBC501A4D2227783CBC501A4D2227783')

    def test_vec2(self):
        self._run_test(b'12345678', b'0182BD0BD4444BF836077A718CCDF409')

    def test_vec3(self):
        self._run_test(b'123456781234567812345678', b'0182BD0BD4444BF826EE41DC2CD6D01B')

    def test_vec4(self):
        self._run_test(b'?><ASdiu92!Z=', b'D2D55E37C0D6A79C844B66B6C7E3E9C4')

    def test_vec5(self):
        self._run_test(b'', b'AAD3B435B51404EEAAD3B435B51404EE')
