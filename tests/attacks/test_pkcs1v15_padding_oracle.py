from samson.oracles.padding_oracle import PaddingOracle
from samson.public_key.rsa import RSA
from samson.attacks.pkcs1v15_padding_oracle_attack import PKCS1v15PaddingOracleAttack
from samson.padding.pkcs1v15_padding import PKCS1v15Padding
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)

key_length = 256
rsa = RSA(key_length)

padding = PKCS1v15Padding(key_length)

def oracle_func(ciphertext):
    plaintext = b'\x00' + rsa.decrypt(ciphertext)
    try:
        padding.unpad(plaintext, allow_padding_oracle=True)
        return True
    except Exception as _:
        return False


class PKCS1v15PaddingOracleAttackTestCase(unittest.TestCase):
    def test_padding_oracle_attack(self):
        oracle = PaddingOracle(oracle_func)

        m = padding.pad(b'kick it, CC')
        c = rsa.encrypt(m)

        assert oracle.check_padding(c)

        attack = PKCS1v15PaddingOracleAttack(oracle)
        self.assertEqual(attack.execute(c, rsa.n, rsa.e, key_length), m)
