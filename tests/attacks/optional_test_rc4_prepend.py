from samson.attacks.rc4_prepend_attack import RC4PrependAttack
from samson.oracles.chosen_plaintext_oracle import ChosenPlaintextOracle
from samson.utilities.general import rand_bytes
from samson.stream_ciphers.rc4 import RC4
#import base64
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)

# For speed reasons
#secret = base64.b64decode(b'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
secret = b'hey'

def random_encrypt(data):
    key = rand_bytes(16)
    cipher = RC4(key)
    plaintext = (data + secret)

    return cipher.generate(len(plaintext)) ^ plaintext



class RC4PrependAttackTestCase(unittest.TestCase):
    def test_prepend_attack(self):
        oracle = ChosenPlaintextOracle(random_encrypt)
        attack = RC4PrependAttack(oracle)

        result = attack.execute(len(secret))
        self.assertEqual(secret, result[0])
