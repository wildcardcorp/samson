from samson.attacks.nostradamus_attack import NostradamusAttack
from samson.primitives.merkle_damgard_construction import MerkleDamgardConstruction
from Crypto.Cipher import AES
from samson.utilities import gen_rand_key, stretch_key, int_to_bytes
from samson.primitives.aes_ecb import encrypt_aes_ecb
import struct
import unittest


hash_size = 2


def compressor(message, state):
    return encrypt_aes_ecb(stretch_key(state, 16), message)[:hash_size]


def padder(message):
    return message


def construction_func(iv, message):
    return MerkleDamgardConstruction(iv, compressor, padder, output_size=hash_size).yield_state(message)


class NostradamusAttackTestCase(unittest.TestCase):
    def test_nostradamus(self):
        attack = NostradamusAttack(k=3, construction_func=construction_func, output_size=hash_size)
        new_message = attack.execute(b'!(')

        hashed_message = MerkleDamgardConstruction(b'!(', compressor, padder, output_size=hash_size).hash(new_message[hash_size:])
        self.assertEqual(hashed_message, attack.crafted_hash)