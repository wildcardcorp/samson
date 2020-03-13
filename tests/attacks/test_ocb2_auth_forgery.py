
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ocb2 import OCB2
from samson.oracles.chosen_plaintext_oracle import ChosenPlaintextOracle
from samson.attacks.ocb_auth_forgery_attack import OCBAuthForgeryAttack
from samson.utilities.bytes import Bytes
import unittest


class OCB2AuthForgeryTestCase(unittest.TestCase):
    def test_gauntlet(self):
        for _ in range(100):
            plaintext = Bytes.random(16)

            rij = Rijndael(Bytes.random(16))
            ocb = OCB2(rij)
            nonce = Bytes.random(16)

            def oracle_func(plaintext, data):
                return ocb.encrypt(nonce, plaintext, data)


            attack = OCBAuthForgeryAttack(ChosenPlaintextOracle(oracle_func))
            tag, ct = attack.execute(plaintext)

            # OCB2 will automatically verify and throw an AssertException if the tag is incorrect
            ocb.decrypt(nonce, (tag, ct), verify=True)
