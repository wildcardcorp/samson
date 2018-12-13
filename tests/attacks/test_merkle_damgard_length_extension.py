from samson.hashes.md4 import MD4
from samson.hashes.md5 import MD5
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA256, SHA512
from samson.hashes.ripemd160 import RIPEMD160
import unittest


class MerkleDamgardLengthExtensionTestCase(unittest.TestCase):
    def test_length_extension(self):
        secret = b'mysecret'
        message = b'mymessage'

        for alg in [MD4(), MD5(), SHA1(), SHA256(), SHA512(), RIPEMD160()]:
            observed = alg.hash(secret + message)
            payload, new_hash = alg.length_extension(observed, message, b'evilbytes!', len(secret))
            self.assertEqual(alg.hash(secret + payload), new_hash)
