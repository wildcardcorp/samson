#!/usr/bin/python3
from samson.utilities import gen_rand_key, pkcs7_pad, pkcs7_unpad, get_blocks, xor_buffs
from samson.primitives.aes_cbc import encrypt_aes_cbc, decrypt_aes_cbc
from samson.attacks.cbc_iv_key_equivalence_attack import CBCIVKeyEquivalenceAttack
import base64
import struct
import unittest

key = gen_rand_key()
iv = key

def sender_encrypt(data):
    return encrypt_aes_cbc(key, iv, data)


def receiver_decrypt(ciphertext):
    plaintext = decrypt_aes_cbc(key, iv, ciphertext, unpad=False)
    if any(int(byte) > 127 for byte in plaintext):
        raise Exception('Bad characters in {}'.format(base64.b64encode(plaintext)))



class CBCIVEquivalenceTestCase(unittest.TestCase):
    def test_equivalence_attack(self):
        plaintext = b'-Super secret message! Hope no one cracks this!-'
        ciphertext = sender_encrypt(plaintext)

        attack = CBCIVKeyEquivalenceAttack(self)
        key_iv, recovered_plaintext = attack.execute(ciphertext)

        self.assertEqual(key_iv, key)
        self.assertEqual(plaintext, recovered_plaintext)

    def request(self, ciphertext):
        try:
            receiver_decrypt(ciphertext)
            return None
        except Exception as e:
            prefix = len('Bad characters in b\'')
            return base64.b64decode(str(e)[prefix:-1])
