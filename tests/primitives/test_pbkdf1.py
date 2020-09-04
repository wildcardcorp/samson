from samson.hashes.sha1 import SHA1
from samson.kdfs.pbkdf1 import PBKDF1

from samson.utilities.bytes import Bytes
import unittest

# https://github.com/Aitordev/Avalanche_PBDFK1/blob/master/test_KDF.py
# https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/SelfTest/Protocol/test_KDF.py
class PBKDF2TestCase(unittest.TestCase):
    def test_vec0(self):
        password        = Bytes(b'password')
        salt            = Bytes(0x78578E5A5D63CB06)
        expected_result = Bytes(0xDC19847E05C64D2FAF10EBFB4A3D2A20)

        kdf = PBKDF1(SHA1(), 16, 1000)
        self.assertEqual(kdf.derive(password, salt), expected_result)
