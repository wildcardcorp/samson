from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from samson.utilities.bytes import Bytes
import hashlib
import unittest

class SHA2TestCase(unittest.TestCase):
    def test_sha2(self):
        for hash_type, reference_method in [(SHA224, hashlib.sha224), (SHA256, hashlib.sha256), (SHA384, hashlib.sha384), (SHA512, hashlib.sha512)]:
            for i in range(9):
                sha2 = hash_type()

                for _ in range(100):
                    in_bytes = Bytes.random(i * 32)
                    self.assertEqual(sha2.hash(in_bytes), reference_method(in_bytes).digest())


    # SHA-512/t test vectors manually generated using pycryptodome
    def _run_512t_test(self, trunc, message, expected_hash):
        sha512t = SHA512(trunc=trunc)
        last = message
        for _ in range(1000):
            last = sha512t.hash(last)

        self.assertEqual(last, expected_hash)


    def test_sha512t_vec0(self):
        trunc         = 256
        message       = Bytes(b'')
        expected_hash = Bytes(0x8FFB6D6180E4C53275F10D62B34789329C69846F2A9E9C6D2DA75B0232EA9466)

        self._run_512t_test(trunc, message, expected_hash)


    def test_sha512t_vec1(self):
        trunc         = 256
        message       = Bytes(b'sampletext')
        expected_hash = Bytes(0xCFD6F9C0EFDA3800700F19875BE2346E49B702A5C2D17261FDB24BBF27DDE4E6)

        self._run_512t_test(trunc, message, expected_hash)


    def test_sha512t_vec2(self):
        trunc         = 224
        message       = Bytes(b'')
        expected_hash = Bytes(0x55BF51615D6950490250EA6DB46065EE086EAD06CF8A1DD969C56F41)

        self._run_512t_test(trunc, message, expected_hash)


    def test_sha512t_vec3(self):
        trunc         = 224
        message       = Bytes(b'sampletext')
        expected_hash = Bytes(0xAD8489322055D0F24980D6D192D77B41BBE286DE82DFEC06BFC1DC11)

        self._run_512t_test(trunc, message, expected_hash)
