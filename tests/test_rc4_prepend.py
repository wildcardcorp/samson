from samson.attacks.rc4_prepend_attack import RC4PrependAttack
from samson.oracles.encryption_oracle import EncryptionOracle
from samson.utilities import gen_rand_key
from Crypto.Cipher import ARC4
import base64
import unittest

# For speed reasons
#secret = base64.b64decode(b'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
secret = b'hey'

def random_encrypt(data):
    key = gen_rand_key(16)
    cipher = ARC4.new(key)
    return cipher.encrypt(data + secret)



class RC4PrependAttackTestCase(unittest.TestCase):
    def test_prepend_attack(self):
        oracle = EncryptionOracle(random_encrypt)
        attack = RC4PrependAttack(oracle)

        result = attack.execute(len(secret))
        self.assertEqual(secret, result[0])