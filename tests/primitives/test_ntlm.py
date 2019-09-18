from samson.hashes.ntlm import NTLM
import unittest

class NTLMTestCase(unittest.TestCase):
    def _run_test(self, plaintext, expected_hash):
        ntlm = NTLM()
        self.assertEqual(ntlm.hash(plaintext).hex().upper(), expected_hash)

    def test_vec0(self):
        self._run_test(b'napier', b'307E40814E7D4E103F6A69B04EA78F3D')

    def test_vec1(self):
        self._run_test(b'aaaaaaaaaaaaaa', b'F523558E22C95C62A6D6D00C841DD32D')

    def test_vec2(self):
        self._run_test(b'12345678', b'259745CB123A52AA2E693AAACCA2DB52')

    def test_vec3(self):
        self._run_test(b'123456781234567812345678', b'D251869E52A6D84D8FA37940EC8FBFD8')

    def test_vec4(self):
        self._run_test(b'?><ASdiu92!Z=', b'834E058A5A4ECB92373F375DA54C889D')

    def test_vec5(self):
        self._run_test(b'', b'31D6CFE0D16AE931B73C59D7E0C089C0')
