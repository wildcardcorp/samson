from samson.prngs.hotp import HOTP
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA256, SHA512
from samson.utilities.bytes import Bytes
import unittest


class DummyCounter(object):
    def __init__(self, value):
        self.value = value


    def get_value(self):
        return self.value


class HOTPTestCase(unittest.TestCase):

    # https://tools.ietf.org/html/rfc4226, Appendix D., pg. 32
    def test_hotp_correctness(self):
        hotp = HOTP(key=Bytes(0x3132333435363738393031323334353637383930))
        expected_values = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]

        self.assertEqual([int(hotp.generate()) for _ in range(len(expected_values))], expected_values)


    # https://tools.ietf.org/html/rfc6238#appendix-B
    def test_totp_correctness(self):
        sha1, sha256, sha512 = SHA1(), SHA256(), SHA512()

        sha1_seed   = Bytes(0x3132333435363738393031323334353637383930)
        sha256_seed = Bytes(0x3132333435363738393031323334353637383930313233343536373839303132)
        sha512_seed = Bytes(0x31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334)

        seed_dict = {
            sha1: sha1_seed,
            sha256: sha256_seed,
            sha512: sha512_seed
        }

        expected_values = [
            (59, '94287082', sha1),
            (59, '46119246', sha256),
            (59, '90693936', sha512),
            (1111111109, '07081804', sha1),
            (1111111109, '68084774', sha256),
            (1111111109, '25091201', sha512),
            (1111111111, '14050471', sha1),
            (1111111111, '67062674', sha256),
            (1111111111, '99943326', sha512),
            (1234567890, '89005924', sha1),
            (1234567890, '91819424', sha256),
            (1234567890, '93441116', sha512)
        ]

        for request_time, expected_code, hash_obj in expected_values:
            hotp = HOTP(key=seed_dict[hash_obj], digits=8, counter=DummyCounter(request_time // 30), hash_obj=hash_obj)
            code = hotp.generate()
            self.assertEqual(code, expected_code)
