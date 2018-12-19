from samson.kdfs.bcrypt_pbkdf import BcryptPBKDF
from samson.utilities.bytes import Bytes
import unittest


# Test vectors generated manually using https://github.com/joyent/node-bcrypt-pbkdf
class BcryptPBKDFTestCase(unittest.TestCase):
    def _run_test(self, password, salt, rounds, key_len, expected_key):
        kdf = BcryptPBKDF(rounds=rounds)
        key = kdf.derive(password, salt, key_len=key_len)

        self.assertEqual(key, expected_key)


    def test_vec0(self):
        password     = Bytes(b'super secret passhphrase')
        salt         = Bytes(b'\xb78\x8fr\xff\xb5\xe4qf,\xa7\xbeY@\xd8>')
        rounds       = 16
        expected_key = Bytes(b'U\x10\x0c\x89\x005\t\xd6\x04\x8a\xe0\xb7w\xc7\xf2\xb5K\x11\xfe\xb9BJ\xfd\x91o<#M\x80\xedc\xdf\xdc\xd7K{-\x91j\xc1\xe7\xfbER\xb7?\x12\xce')

        self._run_test(password, salt, rounds, len(expected_key), expected_key)


    def test_vec1(self):
        password     = Bytes(b'-6\x89(+\x10\xac\xd6\xdc\x95t\xe8K<\xcb\x85\xbf\xfd?\xfb\xec\x8a')
        salt         = Bytes(b'\x1b\x00\x8b\xb0^\xcc\x16\xe4f\x966\x19q\xedL\xda')
        rounds       = 1
        expected_key = Bytes(b"\x9f\x17Xb\xbb<.\x9b0\xc8K\xd4\x9d\x11Z\xa1%j\xf9\xcf\xe6\xc4\xc9\xfb\xb5I\xbd\x97\xcd%x{H\xc6\xda'T\xf4@{\xe5t\xd4\x1a\xb2\x16\xe2\x1f")

        self._run_test(password, salt, rounds, len(expected_key), expected_key)


    def test_vec2(self):
        password     = Bytes(b'\xefQA`G\xf0W\xba\xaa\x18"\xda\xf6\x97\x04;\xf4\xe8\x1b\xbb\x07O\xf0\x0cO\x14:\xfe\x8d\xbf/vyo[')
        salt         = Bytes(b'\xe9A$s6~\xa6\xad\xf2\tM\xa3\x9b\x1c\x85\x84')
        rounds       = 1
        expected_key = Bytes(b'bp<\xf0\x82\t{h\xf4n<\x12H\xe9kYXE\x149\xd7\x10D-\x9cOb\x19\xaf\xa1\x0f\xeda\x0f\x94Y$\x94Y\xe2\x9c\x91\xbb\xb62\xf5\x9a\x95')

        self._run_test(password, salt, rounds, len(expected_key), expected_key)


    def test_vec3(self):
        password     = Bytes(b'\x9b\xe8\x1es')
        salt         = Bytes(b'~i\xec\xee\xf1s\xeb\xf8\xb8j\xc4xi\xb85\n\xc5\x80\x94\xff\xd6\x8f\x92\xd4\xc8\x16\x84\xa8\xc3\xbc')
        rounds       = 2
        expected_key = Bytes(b"\xb6\x83\x9b.D\x7f\xe0\xbe\x13\xb4b\x0blcg\xb0\xa9\xe9\xa2 oGh\x1a\x9ed+w\xa3\x83r|Z9\x90T\x80i'\xd8\xb2\x1d\x13=.z\x16\x12")

        self._run_test(password, salt, rounds, len(expected_key), expected_key)


    def test_vec4(self):
        password     = Bytes(0x0)
        salt         = Bytes(0x0)
        rounds       = 32
        expected_key = Bytes(b'\xfci\xdbK\x0b3\x1d\xc1\x17\x02\x93\xd0\x94\xbc0\xe8\x12]&\x95)0\xbb\x9c\xcfY\x1e\x1af4\xd5\xb5\xa1Q\x18\x04\xb9\x9cH\x03\x0c{\x07\xb4\xefh+7')

        self._run_test(password, salt, rounds, len(expected_key), expected_key)
