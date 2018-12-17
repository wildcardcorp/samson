from samson.attacks.mangers_attack import MangersAttack
from samson.oracles.padding_oracle import PaddingOracle
from samson.utilities.bytes import Bytes
from samson.public_key.rsa import RSA
from samson.padding.oaep import OAEP
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)


class MangersAttackTestCase(unittest.TestCase):
    def test_recover_plaintext(self):
        rsa = RSA(2048)
        oaep = OAEP(rsa.bits)

        plaintext = b'Super secret ;)'
        padded_plain = oaep.pad(plaintext)
        ciphertext = Bytes(rsa.encrypt(padded_plain))

        def oracle_func(attempt):
            pt = rsa.decrypt(attempt.int())
            try:
                oaep.unpad(pt, True)
                return False
            except ValueError as e:
                return "First byte is not zero" in str(e)
            except Exception as e:
                print(e)
                return False


        oracle = PaddingOracle(oracle_func)
        attack = MangersAttack(oracle, rsa)
        recovered_plaintext = oaep.unpad(attack.execute(ciphertext))
        self.assertEqual(recovered_plaintext, plaintext)
