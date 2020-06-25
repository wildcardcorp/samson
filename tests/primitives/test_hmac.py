from samson.macs.hmac import HMAC
import hmac as pyhmac

from samson.hashes.sha3 import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from samson.hashes.md5 import MD5
from samson.hashes.md4 import MD4
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from samson.hashes.blake2 import BLAKE2b, BLAKE2s
from samson.hashes.ripemd160 import RIPEMD160


from samson.utilities.bytes import Bytes
import hashlib
import unittest

class HMACTestCase(unittest.TestCase):
    def _run_tests(self, hash_type, reference_method):
        for i in range(hash_type().block_size // 8):
            for _ in range(100):
                key = Bytes.random(i * 8)
                in_bytes = Bytes.random(i * 32)
                samson_hash = HMAC(key=key, hash_obj=hash_type())
                self.assertEqual(samson_hash.generate(in_bytes), pyhmac.HMAC(key, in_bytes, reference_method).digest())


    def test_md4(self):
        self._run_tests(MD4, lambda: hashlib.new('md4'))


    def test_md5(self):
        self._run_tests(MD5, hashlib.md5)


    def test_sha1(self):
        self._run_tests(SHA1, hashlib.sha1)


    def test_sha2(self):
        for hash_type, reference_method in [(SHA224, hashlib.sha224), (SHA256, hashlib.sha256), (SHA384, hashlib.sha384), (SHA512, hashlib.sha512)]:
            self._run_tests(lambda: hash_type(), reference_method)


    def test_blake2(self):
        self._run_tests(BLAKE2b, hashlib.blake2b)
        self._run_tests(BLAKE2s, hashlib.blake2s)


    def test_ripemd160(self):
        self._run_tests(RIPEMD160, lambda: hashlib.new('ripemd160'))


    def test_sha3(self):
        for hash_type, reference_method in [(SHA3_224, hashlib.sha3_224), (SHA3_256, hashlib.sha3_256), (SHA3_384, hashlib.sha3_384), (SHA3_512, hashlib.sha3_512)]:
            self._run_tests(hash_type, reference_method)
