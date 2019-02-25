from samson.ace.ace import SymEnc, MAC, ACE
from samson.ace.consequence import Consequence
from samson.ace.state import Plaintext
from samson.ace.exploit import KeyPossession
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.cbc import CBC
from samson.public_key.rsa import RSA
from samson.padding.oaep import OAEP
from samson.attacks.cbc_padding_oracle_attack import CBCPaddingOracleAttack
from samson.macs.hmac import HMAC
from samson.attacks.mangers_attack import MangersAttack
from samson.utilities.runtime import RUNTIME
import unittest


CBCPOA  = RUNTIME.exploits[CBCPaddingOracleAttack]
Mangers = RUNTIME.exploits[MangersAttack]

class ACETestCase(unittest.TestCase):
    def _run_test(self, setup, first_msg, receive, expected_exploit_chain, should_succeed):
        ctx = ACE()

        ctx.execute(setup)
        ctx.execute(first_msg)
        ctx.execute(receive)

        if should_succeed:
            exploit_chain = ctx.solve()
            self.assertEqual(exploit_chain, expected_exploit_chain)
        else:
            with self.assertRaises(Exception):
                ctx.solve()



    def test_identity(self):
        def setup(ctx):
            pass

        def first_msg(ctx):
            ctx.perms = Plaintext()

        def receive(ctx):
            ctx.goal(ctx.perms, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [], True)



    def test_never_decrypts(self):
        def setup(ctx):
            ctx.sym_enc = SymEnc(Rijndael, CBC, None)


        def first_msg(ctx):
            perms = Plaintext()
            ctx.enc_perms = ctx.sym_enc.encrypt(perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            ctx.goal(ctx.enc_perms, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, None, False)




    def test_cbc_padding_oracle(self):
        def setup(ctx):
            ctx.sym_enc = SymEnc(Rijndael, CBC, None)


        def first_msg(ctx):
            perms = Plaintext()
            ctx.enc_perms = ctx.sym_enc.encrypt(perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            pt = ctx.sym_enc.decrypt(ctx.enc_perms)
            ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [CBCPOA], True)




    def test_mangers(self):
        def setup(ctx):
            ctx.sym_enc = SymEnc(RSA, OAEP, None)


        def first_msg(ctx):
            perms = Plaintext()
            ctx.enc_perms = ctx.sym_enc.encrypt(perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            pt = ctx.sym_enc.decrypt(ctx.enc_perms)
            ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [Mangers], True)



    def test_double_enc(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)
            ctx.sym_enc  = SymEnc(Rijndael, CBC, None)


        def first_msg(ctx):
            perms = Plaintext()
            ctx.enc_perms = ctx.asym_enc.encrypt(ctx.sym_enc.encrypt(perms))


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            next_enc = ctx.asym_enc.decrypt(ctx.enc_perms)
            pt = ctx.sym_enc.decrypt(next_enc)
            ctx.goal(pt, Consequence.PLAINTEXT_MANIPULATION)


        self._run_test(setup, first_msg, receive, [Mangers, CBCPOA], True)



    def test_double_enc_swapped(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)
            ctx.sym_enc  = SymEnc(Rijndael, CBC, None)


        def first_msg(ctx):
            perms = Plaintext()
            ctx.enc_perms = ctx.sym_enc.encrypt(ctx.asym_enc.encrypt(perms))


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            next_enc = ctx.sym_enc.decrypt(ctx.enc_perms)
            pt = ctx.asym_enc.decrypt(next_enc)
            ctx.goal(pt, Consequence.PLAINTEXT_MANIPULATION)


        self._run_test(setup, first_msg, receive, [CBCPOA, Mangers], True)



    # Decrypt in the wrong order. ACE should complain with a WARNING, and the exploit should fail.
    def test_double_enc_wrong_order(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)
            ctx.sym_enc  = SymEnc(Rijndael, CBC, None)


        def first_msg(ctx):
            perms = Plaintext()
            ctx.enc_perms = ctx.sym_enc.encrypt(ctx.asym_enc.encrypt(perms))


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            next_enc = ctx.asym_enc.decrypt(ctx.enc_perms)
            pt = ctx.sym_enc.decrypt(next_enc)
            ctx.goal(pt, Consequence.PLAINTEXT_MANIPULATION)


        self._run_test(setup, first_msg, receive, None, False)



    def test_encrypt_then_mac(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)
            ctx.sym_enc  = SymEnc(Rijndael, CBC, None)
            ctx.mac      = MAC(HMAC, None)


        def first_msg(ctx):
            perms = Plaintext()
            ctx.enc_perms = ctx.asym_enc.encrypt(ctx.sym_enc.encrypt(perms))
            ctx.enc_perms = ctx.mac.generate(ctx.enc_perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            pt = ctx.mac.validate(ctx.enc_perms)
            pt = ctx.asym_enc.decrypt(pt)
            pt = ctx.sym_enc.decrypt(pt)
            ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, None, False)




    def test_mac_then_encrypt(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)
            ctx.sym_enc  = SymEnc(Rijndael, CBC, None)
            ctx.mac      = MAC(HMAC, None)


        def first_msg(ctx):
            perms = Plaintext()
            perms = ctx.mac.generate(perms)
            ctx.enc_perms = ctx.asym_enc.encrypt(ctx.sym_enc.encrypt(perms))


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            pt = ctx.asym_enc.decrypt(ctx.enc_perms)
            pt = ctx.sym_enc.decrypt(pt)
            pt = ctx.mac.validate(pt)
            ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [Mangers, CBCPOA], True)



    def test_mac_then_encrypt_manipulation(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)
            ctx.sym_enc  = SymEnc(Rijndael, CBC, None)
            ctx.mac      = MAC(HMAC, None)


        def first_msg(ctx):
            perms = Plaintext()
            perms = ctx.mac.generate(perms)
            ctx.enc_perms = ctx.asym_enc.encrypt(ctx.sym_enc.encrypt(perms))


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            pt = ctx.asym_enc.decrypt(ctx.enc_perms)
            pt = ctx.sym_enc.decrypt(pt)
            pt = ctx.mac.validate(pt)
            ctx.goal(pt, Consequence.PLAINTEXT_MANIPULATION)


        self._run_test(setup, first_msg, receive, None, False)



    # Here we generate a symmetric key for Rijndael, encrypt the plaintext, and then encrypt the key
    # using RSA-OAEP.
    def test_enc_key_and_decrypt(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)


        def first_msg(ctx):
            perms         = Plaintext()
            key           = Plaintext()
            ctx.enc_key   = ctx.asym_enc.encrypt(key)

            sym_enc       = SymEnc(Rijndael, CBC, key)
            ctx.enc_perms = sym_enc.encrypt(perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)
            ctx.enc_key.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            key = ctx.asym_enc.decrypt(ctx.enc_key)
            pt  = SymEnc(Rijndael, CBC, key).decrypt(ctx.enc_perms)
            ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [CBCPOA], True)



    # Same thing as above, but we put in a wrong key.
    def test_enc_key_and_decrypt_wrong_key(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)


        def first_msg(ctx):
            perms         = Plaintext()
            key           = Plaintext()
            wrong_key     = Plaintext()
            ctx.enc_key   = ctx.asym_enc.encrypt(wrong_key)

            sym_enc       = SymEnc(Rijndael, CBC, key)
            ctx.enc_perms = sym_enc.encrypt(perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)
            ctx.enc_key.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            key = ctx.asym_enc.decrypt(ctx.enc_key)
            pt  = SymEnc(Rijndael, CBC, key).decrypt(ctx.enc_perms)
            ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, None, False)



    # In this cryptosystem, we only MAC the perms ciphertext but not the encrypted key.
    def test_enc_key_and_mac_key_recovery(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)


        def first_msg(ctx):
            perms         = Plaintext()
            key           = Plaintext()
            ctx.enc_key   = ctx.asym_enc.encrypt(key)

            sym_enc       = SymEnc(Rijndael, CBC, key)
            ctx.enc_perms = sym_enc.encrypt(perms)

            mac           = MAC(HMAC, key)
            ctx.enc_perms = mac.generate(ctx.enc_perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)
            ctx.enc_key.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            key = ctx.asym_enc.decrypt(ctx.enc_key)

            mac = MAC(HMAC, key)
            pt  = mac.validate(ctx.enc_perms)
            pt  = SymEnc(Rijndael, CBC, key).decrypt(pt)
            ctx.goal(key, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [Mangers], True)



    # This is basically the same as above, but this time we're asking for the plaintext.
    # This should still work. Even though the MAC is protecting the perms ciphertext,
    # we should be able to perform the key recovery and then the plaintext recovery.
    def test_enc_key_and_mac_pt_recovery(self):
        def setup(ctx):
            ctx.asym_enc = SymEnc(RSA, OAEP, None)


        def first_msg(ctx):
            perms         = Plaintext()
            key           = Plaintext()
            ctx.enc_key   = ctx.asym_enc.encrypt(key)

            sym_enc       = SymEnc(Rijndael, CBC, key)
            ctx.enc_perms = sym_enc.encrypt(perms)

            mac           = MAC(HMAC, key)
            ctx.enc_perms = mac.generate(ctx.enc_perms)


        def receive(ctx):
            # The attacker can manipulate the ciphertext
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)
            ctx.enc_key.propagate_requirement_satisfied(Consequence.PLAINTEXT_MANIPULATION)

            key = ctx.asym_enc.decrypt(ctx.enc_key)

            mac = MAC(HMAC, key)
            pt  = mac.validate(ctx.enc_perms)
            pt  = SymEnc(Rijndael, CBC, key).decrypt(pt)
            ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [[Mangers], KeyPossession()], True)



    def test_enc_key_but_we_have_the_key(self):
        def setup(ctx):
            key         = Plaintext()
            ctx.sym_enc = SymEnc(Rijndael, CBC, key)


        def first_msg(ctx):
            perms         = Plaintext()
            ctx.enc_perms = ctx.sym_enc.encrypt(perms)


        def receive(ctx):
            ctx.enc_perms.propagate_requirement_satisfied(Consequence.KEY_RECOVERY)
            ctx.goal(ctx.enc_perms, Consequence.PLAINTEXT_RECOVERY)


        self._run_test(setup, first_msg, receive, [KeyPossession()], True)
