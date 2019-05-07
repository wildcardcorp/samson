from samson.kdfs.concatkdf import ConcatKDF
from samson.hashes.sha2 import SHA256
import unittest


# Generated using 'cryptography'

# import os
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
# from cryptography.hazmat.backends import default_backend
# backend = default_backend()
# otherinfo = os.urandom(16)
# key = os.urandom(8)
# ckdf = ConcatKDFHash(
#     algorithm=hashes.SHA256(),
#     length=32,
#     otherinfo=otherinfo,
#     backend=backend
# )
# derived = ckdf.derive(key)

# print(key)
# print(otherinfo)
# print(derived)

class ConcatKDFUnittest(unittest.TestCase):
    def _run_test(self, key, length, other_info, expected_derived):
        kdf = ConcatKDF(SHA256(), length)
        self.assertEqual(kdf.derive(key, other_info), expected_derived)


    def test_vec0(self):
        key        = b'\x90\x88\x12\xbe\xba\x0b~\xca'
        other_info = b'\xbf\xa8\x83\xe2G\x912\x11h\xc0\xf4>\xb3\xf2Mo'
        length     = 32

        derived    = b'^\x93e\xc7\x9a\xd0g\r\xcb\xaa\x9b\xfck\xdd\xe0\rx\x1b\xde\xf6:p\x19\xd6M\xa5\x11\xf5\xa1\xbd\x8c\x8b'

        self._run_test(key, length, other_info, derived)


    def test_vec1(self):
        key        = b'\x81\xeb\xba%\xf8\x852\x97'
        other_info = b'\x00\xfe\xa4elk\x9d\x9d\xf7I\xd4aqU\x15\xae'
        length     = 32

        derived    = b'\xdc*\xc0\x07\x89\xfaLf\x1bq\x8d\x0b\xf8\xfb\xf0\xc1\x0c^\xcd\x98\x8f`\xf6\xa9\x07l\xaf\xf2\xd7\xc8v\xb1'

        self._run_test(key, length, other_info, derived)


    def test_vec2(self):
        key        = b'\x98\x89\x99\xd0\xe4<\xe2o'
        other_info = b'\x1e~u\xb4\xb1kA}\xa5F\xfb\xd2\x0b\xb7\xc0\xc2'
        length     = 48

        derived    = b'03\x8fw\xb3\x9dq]\xf8\xc7\xd1"_\x1dH\xf3\x1c\xc58e\xd1\xb9[\xa4@\xe2o\x88\xa7\xe5\x1aD\xd9WcG\xe5C\x85"\xd9T#u\x7f\x87!I'

        self._run_test(key, length, other_info, derived)


    def test_vec3(self):
        key        = b'\xc4\xb7ntC,\xa0\x9b'
        other_info = b'o\xfc\x99\xa5\xcd\xf1\xd8\x0et\x88\x80\xc6\x80\x88\xe1\x83'
        length     = 64

        derived    = b'+\xcb\x8b\xdf\x88Y\xbd>\xa1\xe9\xddCkL\x10R\xce\xdb3\xd4C4\xc2\xa6,C\x8b\xb8\x93\x1b\xcb\x89\xd8\xd7\xa4,\xa6\x8b\xa1\xfd\xfa\\\xd8\xf5\xdch\xf1\xc7\xca\x19c\xf0xmS\xab\x84\xef5:h\x96\x8b\x13'

        self._run_test(key, length, other_info, derived)
