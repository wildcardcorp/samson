from samson.kdfs.s2v import S2V
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import unittest

# https://tools.ietf.org/html/rfc5297#appendix-A
class S2VTestCase(unittest.TestCase):
    def _run_test(self, key, strings, expected_iv):
        s2v = S2V(Rijndael(key))

        derived_iv = s2v.derive(*strings)
        self.assertEqual(derived_iv, expected_iv)


    def test_vec0(self):
        key          = Bytes(0xFFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0)
        ad           = Bytes(0x101112131415161718191a1b1c1d1e1f2021222324252627)
        pt           = Bytes(0x112233445566778899aabbccddee)
        expected_tag = Bytes(0x85632d07c6e8f37f950acd320a2ecc93)

        self._run_test(key, [ad, pt], expected_tag)


    def test_vec1(self):
        key          = Bytes(0x7f7e7d7c7b7a79787776757473727170)
        ad_1         = Bytes(0x00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100).zfill(40)
        ad_2         = Bytes(0x102030405060708090a0)
        nonce        = Bytes(0x09f911029d74e35bd84156c5635688c0)
        pt           = Bytes(0x7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553)
        expected_tag = Bytes(0x7bdb6e3b432667eb06f4d14bff2fbd0f)

        self._run_test(key, [ad_1, ad_2, nonce, pt], expected_tag)
