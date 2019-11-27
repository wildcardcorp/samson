from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.ocb2 import OCB2
from samson.block_ciphers.rijndael import Rijndael
import unittest

# http://web.cs.ucdavis.edu/~rogaway/papers/draft-krovetz-ocb-00.txt
class OCB2TestCase(unittest.TestCase):
    def _run_test(self, key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext):
        rij  = Rijndael(key)
        ocb2 = OCB2(rij)
        ciphertext = ocb2.encrypt(nonce, plaintext, auth_data)

        self.assertEqual(ciphertext, (expected_tag, expected_ciphertext))
        self.assertEqual(ocb2.decrypt(nonce, ciphertext, auth_data), plaintext)


    def test_vec0(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(b'')
        auth_data = Bytes(b'')

        expected_tag        = Bytes(0xBF3108130773AD5EC70EC69E7875A7B0)
        expected_ciphertext = Bytes(b'')

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec1(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x0001020304050607).zfill(8)
        auth_data = Bytes(b'')

        expected_tag        = Bytes(0xA45F5FDEA5C088D1D7C8BE37CABC8C5C)
        expected_ciphertext = Bytes(0xC636B3A868F429BB)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec2(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        auth_data = Bytes(b'')

        expected_tag        = Bytes(0xF7EE49AE7AA5B5E6645DB6B3966136F9)
        expected_ciphertext = Bytes(0x52E48F5D19FE2D9869F0C4A4B3D2BE57)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec3(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F1011121314151617).zfill(24)
        auth_data = Bytes(b'')

        expected_tag        = Bytes(0xA1A50F822819D6E0A216784AC24AC84C)
        expected_ciphertext = Bytes(0xF75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec4(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F).zfill(32)
        auth_data = Bytes(b'')

        expected_tag        = Bytes(0x09CA6C73F0B5C6C5FD587122D75F2AA3)
        expected_ciphertext = Bytes(0xF75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec5(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627).zfill(40)
        auth_data = Bytes(b'')

        expected_tag        = Bytes(0x9DB0CDF880F73E3E10D4EB3217766688)
        expected_ciphertext = Bytes(0xF75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec6(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x0001020304050607).zfill(8)
        auth_data = Bytes(0x0001020304050607).zfill(8)

        expected_tag        = Bytes(0x8D059589EC3B6AC00CA31624BC3AF2C6)
        expected_ciphertext = Bytes(0xC636B3A868F429BB)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec7(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        auth_data = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)

        expected_tag        = Bytes(0x4DA4391BCAC39D278C7A3F1FD39041E6)
        expected_ciphertext = Bytes(0x52E48F5D19FE2D9869F0C4A4B3D2BE57)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec8(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F1011121314151617).zfill(24)
        auth_data = Bytes(0x000102030405060708090A0B0C0D0E0F1011121314151617).zfill(24)

        expected_tag        = Bytes(0x24B9AC3B9574D2202678E439D150F633)
        expected_ciphertext = Bytes(0xF75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec9(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F).zfill(32)
        auth_data = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F).zfill(32)

        expected_tag        = Bytes(0x41A977C91D66F62C1E1FC30BC93823CA)
        expected_ciphertext = Bytes(0xF75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)


    def test_vec10(self):
        key       = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        nonce     = Bytes(0x000102030405060708090A0B0C0D0E0F).zfill(16)
        plaintext = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627).zfill(40)
        auth_data = Bytes(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627).zfill(40)

        expected_tag        = Bytes(0x65A92715A028ACD4AE6AFF4BFAA0D396)
        expected_ciphertext = Bytes(0xF75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C)

        self._run_test(key, plaintext, nonce, auth_data, expected_tag, expected_ciphertext)
