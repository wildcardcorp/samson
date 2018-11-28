from samson.utilities.bytes import Bytes
from samson.publickey.ed448 import Ed448
from samson.utilities.ecc import EdwardsCurve25519, EdwardsCurve448
from samson.hashes.sha2 import SHA2
from samson.hashes.sha3 import SHA3
import unittest

# https://tools.ietf.org/html/rfc8032#section-7.1
class Ed448TestCase(unittest.TestCase):
    def _run_test(self, message, d, curve, hash_alg, expected_public_key=None, expected_sig=None):
        eddsa = Ed448(d=d, curve=curve, hash_obj=hash_alg)
        sig = eddsa.sign(message)

        if expected_public_key:
            print(eddsa.encode_point(eddsa.A).int())
            print(expected_public_key)
            self.assertEqual(eddsa.encode_point(eddsa.A).int(), expected_public_key)

        if expected_sig:
            self.assertEqual(sig, expected_sig)

        # self.assertTrue(eddsa.verify(message, sig))


    def _run_448_test(self, message, d, expected_public_key=None, expected_sig=None):
        curve    = EdwardsCurve448
        hash_alg = SHA3.SHAKE256(912)
        self._run_test(message, d, curve, hash_alg, expected_public_key, expected_sig)


    def test_vec0(self):
        message             = Bytes(b'')
        d                   = 0x6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b
        expected_public_key = Bytes(0x5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180)[::-1].int()
        expected_sig        = Bytes(0x533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600)

        self._run_448_test(message, d, expected_public_key, expected_sig)