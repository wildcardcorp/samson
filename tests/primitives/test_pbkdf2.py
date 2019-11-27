from samson.macs.hmac import HMAC
from samson.kdfs.pbkdf2 import PBKDF2

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

class PBKDF2TestCase(unittest.TestCase):
    def _run_tests(self, hash_type, reference_method):
        hash_fn = lambda password, salt: HMAC(password, hash_type()).generate(salt)

        for i in range(hash_type().block_size // 8):
            for _ in range(5):
                password = Bytes.random(i * 8).zfill((i + 1) * 8)
                salt = Bytes.random(i * 2)
                desired_len = max(1, Bytes.random(1).int())
                num_iters = Bytes.random(1).int() % 256 + 1

                pbkdf2 = PBKDF2(hash_fn=hash_fn, desired_len=desired_len, num_iters=num_iters)
                self.assertEqual(pbkdf2.derive(password, salt), hashlib.pbkdf2_hmac(reference_method, password, salt, num_iters, desired_len))


    def test_md4(self):
        self._run_tests(MD4, 'md4')


    def test_md5(self):
        self._run_tests(MD5, 'md5')


    def test_sha1(self):
        self._run_tests(SHA1, 'sha1')


    def test_sha2(self):
        for hash_type, reference_method in [(SHA224, 'sha224'), (SHA256, 'sha256'), (SHA384, 'sha384'), (SHA512, 'sha512')]:
            self._run_tests(lambda: hash_type(), reference_method)


    def test_blake2(self):
        self._run_tests(BLAKE2b, 'blake2b')
        self._run_tests(BLAKE2s, 'blake2s')


    def test_ripemd160(self):
        self._run_tests(RIPEMD160, 'ripemd160')


    def test_sha3(self):
        for hash_type, reference_method in [(SHA3_224, 'sha3_224'), (SHA3_256, 'sha3_256'), (SHA3_384, 'sha3_384'), (SHA3_512, 'sha3_512')]:
            self._run_tests(hash_type, reference_method)
