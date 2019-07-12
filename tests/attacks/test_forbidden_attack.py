from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.gcm import GCM
from samson.attacks.forbidden_attack import ForbiddenAttack
from samson.utilities.bytes import Bytes
import unittest


class ForbiddenAttackTestCase(unittest.TestCase):
    def test(self):
        rij = Rijndael(Bytes.random(32))
        gcm = GCM(rij.encrypt)
        nonce = Bytes.random(12)

        ad_a = Bytes.random(8)
        ad_b = Bytes.random(24)

        pt_a = Bytes.random(16)
        pt_b = Bytes.random(16)

        ciphertext_a = gcm.encrypt(plaintext=pt_a, nonce=nonce, data=ad_a)
        ciphertext_b = gcm.encrypt(plaintext=pt_b, nonce=nonce, data=ad_b)

        ciphertext_a, tag_a = ciphertext_a[:-16], ciphertext_a[-16:]
        ciphertext_b, tag_b = ciphertext_b[:-16], ciphertext_b[-16:]

        attack = ForbiddenAttack()
        candidates = attack.execute(ad_a, ciphertext_a, tag_a, ad_b, ciphertext_b, tag_b)

        self.assertTrue(gcm.H in candidates)
