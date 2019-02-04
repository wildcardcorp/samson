from samson.block_ciphers.modes.siv import SIV
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import unittest

# https://tools.ietf.org/html/rfc5297#appendix-A
class SIVTestCase(unittest.TestCase):
    def _run_test(self, rij_key, siv_key, plaintext, additional_data, expected_ciphertext):
        rij = Rijndael(rij_key)
        siv = SIV(siv_key, rij)

        ciphertext = siv.encrypt(plaintext, additional_data)
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(siv.decrypt(ciphertext, additional_data), plaintext)


    def test_vec0(self):
        rij_key             = Bytes(0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff)
        siv_key             = Bytes(0xFFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0)
        ad                  = Bytes(0x101112131415161718191a1b1c1d1e1f2021222324252627)
        pt                  = Bytes(0x112233445566778899aabbccddee)
        expected_ciphertext = Bytes(0x85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c)

        self._run_test(rij_key, siv_key, pt, [ad], expected_ciphertext)


    def test_vec1(self):
        rij_key             = Bytes(0x404142434445464748494a4b4c4d4e4f)
        siv_key             = Bytes(0x7f7e7d7c7b7a79787776757473727170)
        ad_1                = Bytes(0x00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100).zfill(40)
        ad_2                = Bytes(0x102030405060708090a0)
        nonce               = Bytes(0x09f911029d74e35bd84156c5635688c0)
        pt                  = Bytes(0x7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553)
        expected_ciphertext = Bytes(0x7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d)

        self._run_test(rij_key, siv_key, pt, [ad_1, ad_2, nonce], expected_ciphertext)
