from samson.oracles.padding_oracle import PaddingOracle
from samson.primitives.rsa import RSA
from samson.utilities.padding import pkcs15_pad
from samson.attacks.pkcs15_padding_oracle_attack import PKCS15PaddingOracleAttack, _ceil
import unittest

key_length = 256
rsa = RSA(key_length)

def oracle_func(ciphertext):
    plaintext = b'\x00' + rsa.decrypt(ciphertext)
    return plaintext[:2] == b'\x00\x02' and len(plaintext) == _ceil(rsa.n.bit_length(), 8)


class PKCS15PaddingOracleAttackTestCase(unittest.TestCase):
    def test_padding_oracle_attack(self):
        oracle = PaddingOracle(oracle_func)

        m = pkcs15_pad(b'kick it, CC', key_length // 8)
        c = rsa.encrypt(m)

        assert oracle.check_padding(c)

        attack = PKCS15PaddingOracleAttack(oracle)
        self.assertEqual(attack.execute(c, rsa.n, rsa.e, key_length), m)