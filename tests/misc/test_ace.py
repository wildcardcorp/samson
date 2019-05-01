from samson.ace.ace import SymEnc, MAC, ACE, AsymmetricKey
from samson.ace.consequence import Consequence, Manipulation
from samson.ace.state import Plaintext
from samson.ace.exploit import KeyPossession
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.cbc import CBC
from samson.public_key.rsa import RSA
from samson.stream_ciphers.rc4 import RC4, RC4PrependAttack
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



    # def test_identity(self):
    #     def setup(ctx):
    #         pass

    #     def first_msg(ctx):
    #         ctx.perms = Plaintext()

    #     def receive(ctx):
    #         ctx.reveal(ctx.perms)
    #         ctx.goal(ctx.perms, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [], True)



    # def test_never_decrypts(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         ctx.goal(ctx.enc_perms, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, None, False)




    # def test_cbc_padding_oracle(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         pt = ctx.sym_enc.decrypt(ctx.enc_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [CBCPOA], True)




    # def test_mangers(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(RSA, OAEP, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         pt = ctx.sym_enc.decrypt(ctx.enc_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [Mangers], True)



    # def test_double_enc(self):
    #     def setup(ctx):
    #         ctx.asym_enc = SymEnc(RSA, OAEP, Plaintext())
    #         ctx.sym_enc  = SymEnc(Rijndael, CBC, Plaintext())


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.asym_enc.encrypt(ctx.sym_enc.encrypt(perms))


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         next_enc = ctx.asym_enc.decrypt(ctx.enc_perms)
    #         pt = ctx.sym_enc.decrypt(next_enc)
    #         ctx.goal(pt, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, None, False)



    # def test_double_enc_bypass(self):
    #     def setup(ctx):
    #         ctx.stream_enc = SymEnc(RC4, None, None)
    #         ctx.sym_enc    = SymEnc(Rijndael, CBC, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.stream_enc.encrypt(ctx.sym_enc.encrypt(perms))


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         next_enc = ctx.stream_enc.decrypt(ctx.enc_perms)
    #         pt = ctx.sym_enc.decrypt(next_enc)
    #         ctx.goal(pt, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, [CBCPOA], True)



    # # Decrypt in the wrong order. ACE should complain with a WARNING, and the exploit should fail.
    # def test_double_enc_wrong_order(self):
    #     def setup(ctx):
    #         ctx.asym_enc = SymEnc(RSA, OAEP, None)
    #         ctx.sym_enc  = SymEnc(Rijndael, CBC, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(ctx.asym_enc.encrypt(perms))


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)

    #         next_enc = ctx.asym_enc.decrypt(ctx.enc_perms)
    #         pt = ctx.sym_enc.decrypt(next_enc)

    #         # Literally give the attacker the goal
    #         pt.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.goal(pt, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, None, False)



    # def test_just_mac_pt_recovery(self):
    #     def setup(ctx):
    #         ctx.mac = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         ctx.perms  = Plaintext()
    #         ctx.enc_mac = ctx.mac.generate(ctx.perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.perms)
    #         ctx.reveal(ctx.enc_mac)

    #         _ = ctx.mac.validate(ctx.enc_mac)
    #         ctx.goal(ctx.perms, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [], True)



    # def test_just_mac_pt_manipulation(self):
    #     def setup(ctx):
    #         ctx.mac = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         ctx.perms   = Plaintext()
    #         ctx.enc_mac = ctx.mac.generate(ctx.perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.perms)
    #         ctx.reveal(ctx.enc_mac)

    #         _ = ctx.mac.validate(ctx.enc_mac)
    #         ctx.goal(ctx.perms, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, None, False)



    # def test_just_mac_twice(self):
    #     def setup(ctx):
    #         ctx.mac = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         ctx.perms   = Plaintext()
    #         ctx.enc_mac_a = ctx.mac.generate(ctx.perms)
    #         ctx.enc_mac_b = ctx.mac.generate(ctx.perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.perms)
    #         ctx.reveal(ctx.enc_mac_a)
    #         ctx.reveal(ctx.enc_mac_b)

    #         _ = ctx.mac.validate(ctx.enc_mac_a)
    #         _ = ctx.mac.validate(ctx.enc_mac_b)
    #         ctx.goal(ctx.perms, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [], True)



    # def test_just_mac_no_validation(self):
    #     def setup(ctx):
    #         ctx.mac = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         ctx.perms   = Plaintext()
    #         ctx.enc_mac = ctx.mac.generate(ctx.perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.perms)
    #         ctx.reveal(ctx.enc_mac)

    #         ctx.goal(ctx.perms, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, [], True)


    # # TODO: We shouldn't have to specify Consequence.KEY_RECOVERY; we should just have to revealed the key
    # def test_just_mac_key_reveal(self):
    #     def setup(ctx):
    #         ctx.mac = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         ctx.perms   = Plaintext()
    #         ctx.enc_mac = ctx.mac.generate(ctx.perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.perms)
    #         ctx.reveal(ctx.enc_mac)

    #         ctx.enc_mac.propagate_requirement_satisfied(Consequence.KEY_RECOVERY)

    #         _ = ctx.mac.validate(ctx.enc_mac)
    #         ctx.goal(ctx.perms, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, [KeyPossession()], True)


    # def test_double_mac_single_reveal(self):
    #     def setup(ctx):
    #         ctx.mac_a = MAC(HMAC, Plaintext())
    #         ctx.mac_b = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         ctx.perms  = Plaintext()
    #         ctx.enc_mac_a = ctx.mac_a.generate(ctx.perms)
    #         ctx.enc_mac_b = ctx.mac_b.generate(ctx.perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.perms)
    #         ctx.reveal(ctx.enc_mac_a)
    #         ctx.reveal(ctx.enc_mac_b)
    #         ctx.reveal(ctx.mac_a.key)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_mac_a.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_mac_b.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         _ = ctx.mac_a.validate(ctx.enc_mac_a)
    #         _ = ctx.mac_b.validate(ctx.enc_mac_b)
    #         ctx.goal(ctx.perms, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, None, False)



    def test_double_mac_double_reveal(self):
        def setup(ctx):
            ctx.mac_a = MAC(HMAC, Plaintext())
            ctx.mac_b = MAC(HMAC, Plaintext())


        def first_msg(ctx):
            ctx.perms  = Plaintext()
            ctx.enc_mac_a = ctx.mac_a.generate(ctx.perms)
            ctx.enc_mac_b = ctx.mac_b.generate(ctx.perms)


        def receive(ctx):
            ctx.taint(ctx.perms)

            # ACTUALLY, this SHOULDN'T work if we just reveal them. We need to be able
            # to REPLACE (read Manip.BIT_LEVEL).

            ctx.reveal(ctx.enc_mac_a)
            ctx.reveal(ctx.enc_mac_b)

            # The attacker has the key
            ctx.enc_mac_a.propagate_requirement_satisfied(Consequence.KEY_RECOVERY)
            ctx.enc_mac_b.propagate_requirement_satisfied(Consequence.KEY_RECOVERY)

            _ = ctx.mac_a.validate(ctx.enc_mac_a)
            _ = ctx.mac_b.validate(ctx.enc_mac_b)
            ctx.goal(ctx.perms, Manipulation.PT_BIT_LEVEL)


        self._run_test(setup, first_msg, receive, None, False)


    # def test_double_mac_double_taint(self):
    #     def setup(ctx):
    #         ctx.mac_a = MAC(HMAC, Plaintext())
    #         ctx.mac_b = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         ctx.perms  = Plaintext()
    #         ctx.enc_mac_a = ctx.mac_a.generate(ctx.perms)
    #         ctx.enc_mac_b = ctx.mac_b.generate(ctx.perms)


    #     def receive(ctx):
    #         ctx.taint(ctx.perms)

    #         ctx.taint(ctx.enc_mac_a)
    #         ctx.taint(ctx.enc_mac_b)

    #         # The attacker has the key
    #         ctx.enc_mac_a.propagate_requirement_satisfied(Consequence.KEY_RECOVERY)
    #         ctx.enc_mac_b.propagate_requirement_satisfied(Consequence.KEY_RECOVERY)

    #         _ = ctx.mac_a.validate(ctx.enc_mac_a)
    #         _ = ctx.mac_b.validate(ctx.enc_mac_b)
    #         ctx.goal(ctx.perms, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, [KeyPossession()], True)



    # def test_encrypt_then_mac(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, None)
    #         ctx.mac     = MAC(HMAC, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)
    #         ctx.enc_mac = ctx.mac.generate(ctx.enc_perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.enc_mac)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_mac.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         _ = ctx.mac.validate(ctx.enc_mac)
    #         pt = ctx.sym_enc.decrypt(ctx.enc_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, None, False)



    # # Secure... except we also give the attacker the plaintext
    # def test_encrypt_then_mac_but_give_pt(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, None)
    #         ctx.mac     = MAC(HMAC, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)
    #         ctx.enc_mac = ctx.mac.generate(ctx.enc_perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.enc_mac)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_mac.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         _ = ctx.mac.validate(ctx.enc_mac)
    #         pt = ctx.sym_enc.decrypt(ctx.enc_perms)

    #         # Woops
    #         ctx.reveal(pt)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [], True)




    # def test_encrypt_then_mac_dont_check(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, None)
    #         ctx.mac     = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)
    #         ctx.enc_mac = ctx.mac.generate(ctx.enc_perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.enc_mac)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_mac.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         pt = ctx.sym_enc.decrypt(ctx.enc_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [CBCPOA], True)



    # def test_mac_then_encrypt(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, Plaintext())
    #         ctx.mac     = MAC(HMAC, Plaintext())


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         ctx.mac_perms = ctx.mac.generate(perms)
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.mac_perms)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         pt = ctx.sym_enc.decrypt(ctx.enc_perms)
    #         _ = ctx.mac.validate(ctx.mac_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [CBCPOA], True)



    # def test_mac_then_encrypt_manipulation(self):
    #     def setup(ctx):
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, None)
    #         ctx.mac     = MAC(HMAC, None)


    #     def first_msg(ctx):
    #         perms = Plaintext()
    #         perms = ctx.mac.generate(perms)
    #         ctx.enc_perms = ctx.sym_enc.encrypt(perms)


    #     def receive(ctx):
    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         pt = ctx.sym_enc.decrypt(ctx.enc_perms)
    #         pt = ctx.mac.validate(pt)
    #         ctx.goal(pt, Manipulation.PT_BIT_LEVEL)


    #     self._run_test(setup, first_msg, receive, None, False)



    # # Here we generate a symmetric key for Rijndael, encrypt the plaintext, and then encrypt the key
    # # using RSA-OAEP.
    # def test_enc_key_and_decrypt(self):
    #     def setup(ctx):
    #         ctx.asym_enc = SymEnc(RSA, OAEP, None)


    #     def first_msg(ctx):
    #         perms         = Plaintext()
    #         key           = Plaintext()
    #         ctx.enc_key   = ctx.asym_enc.encrypt(key)

    #         sym_enc       = SymEnc(Rijndael, CBC, key)
    #         ctx.enc_perms = sym_enc.encrypt(perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.enc_key)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_key.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         key = ctx.asym_enc.decrypt(ctx.enc_key)
    #         pt  = SymEnc(Rijndael, CBC, key).decrypt(ctx.enc_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [CBCPOA], True)



    # # Same thing as above, but we put in a wrong key.
    # def test_enc_key_and_decrypt_wrong_key(self):
    #     def setup(ctx):
    #         ctx.asym_enc = SymEnc(RSA, OAEP, None)


    #     def first_msg(ctx):
    #         perms         = Plaintext()
    #         key           = Plaintext()
    #         wrong_key     = Plaintext()
    #         ctx.enc_key   = ctx.asym_enc.encrypt(wrong_key)

    #         sym_enc       = SymEnc(Rijndael, CBC, key)
    #         ctx.enc_perms = sym_enc.encrypt(perms)


    #     def receive(ctx):
    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_key.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         key = ctx.asym_enc.decrypt(ctx.enc_key)
    #         pt  = SymEnc(Rijndael, CBC, key).decrypt(ctx.enc_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, None, False)



    # # In this cryptosystem, we only MAC the perms ciphertext but not the encrypted key.
    # def test_enc_key_and_mac_key_recovery(self):
    #     def setup(ctx):
    #         ctx.asym_enc = SymEnc(RSA, OAEP, None)


    #     def first_msg(ctx):
    #         perms         = Plaintext()
    #         key           = Plaintext()
    #         ctx.enc_key   = ctx.asym_enc.encrypt(key)

    #         sym_enc       = SymEnc(Rijndael, CBC, key)
    #         ctx.enc_perms = sym_enc.encrypt(perms)

    #         mac           = MAC(HMAC, key)
    #         ctx.enc_perms = mac.generate(ctx.enc_perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.enc_key)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_key.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         key = ctx.asym_enc.decrypt(ctx.enc_key)

    #         mac = MAC(HMAC, key)
    #         pt  = mac.validate(ctx.enc_perms)
    #         pt  = SymEnc(Rijndael, CBC, key).decrypt(pt)
    #         ctx.goal(key, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [Mangers], True)



    # # This is basically the same as above, but this time we're asking for the plaintext.
    # # This should still work. Even though the MAC is protecting the perms ciphertext,
    # # we should be able to perform the key recovery and then the plaintext recovery.
    # def test_enc_key_and_mac_pt_recovery(self):
    #     def setup(ctx):
    #         ctx.asym_enc = SymEnc(RSA, OAEP, None)


    #     def first_msg(ctx):
    #         perms         = Plaintext()
    #         key           = Plaintext()
    #         ctx.enc_key   = ctx.asym_enc.encrypt(key)

    #         sym_enc       = SymEnc(Rijndael, CBC, key)
    #         ctx.enc_perms = sym_enc.encrypt(perms)

    #         mac           = MAC(HMAC, key)
    #         ctx.mac_perms = mac.generate(ctx.enc_perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.enc_key)
    #         ctx.reveal(ctx.mac_perms)

    #         # The attacker can manipulate the ciphertext
    #         ctx.enc_perms.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)
    #         ctx.enc_key.propagate_requirement_satisfied(Manipulation.PT_BIT_LEVEL)

    #         key = ctx.asym_enc.decrypt(ctx.enc_key)

    #         mac = MAC(HMAC, key)
    #         _  = mac.validate(ctx.mac_perms)
    #         pt  = SymEnc(Rijndael, CBC, key).decrypt(ctx.enc_perms)
    #         ctx.goal(pt, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [[Mangers], KeyPossession()], True)



    # def test_enc_key_but_we_have_the_key(self):
    #     def setup(ctx):
    #         key         = Plaintext()
    #         ctx.sym_enc = SymEnc(Rijndael, CBC, key)


    #     def first_msg(ctx):
    #         ctx.perms     = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(ctx.perms)


    #     def receive(ctx):
    #         # Give the attacker the key
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.enc_perms.propagate_requirement_satisfied(Consequence.KEY_RECOVERY)

    #         ctx.goal(ctx.perms, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [KeyPossession()], True)



    # def test_asymmetric(self):
    #     def setup(ctx):
    #         key         = Plaintext()
    #         ctx.sym_enc = SymEnc(RSA, OAEP, key)


    #     def first_msg(ctx):
    #         perms         = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.decrypt(perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)

    #         # Give the attacker the key
    #         #ctx.enc_perms.propagate_requirement_satisfied(Consequence.)

    #         ctx.goal(ctx.enc_perms, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [KeyPossession()], True)



    # def test_asymmetric(self):
    #     def setup(ctx):
    #         ctx.key     = AsymmetricKey(size=2048)
    #         ctx.sym_enc = SymEnc(RSA, OAEP, ctx.key.private)


    #     def first_msg(ctx):
    #         ctx.perms     = Plaintext()
    #         ctx.enc_perms = ctx.sym_enc.encrypt(ctx.perms)


    #     def receive(ctx):
    #         ctx.reveal(ctx.enc_perms)
    #         ctx.reveal(ctx.key.public)
    #         ctx.goal(ctx.perms, Consequence.PLAINTEXT_RECOVERY)


    #     self._run_test(setup, first_msg, receive, [KeyPossession()], True)
