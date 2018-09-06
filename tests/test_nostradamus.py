from samson.attacks.nostradamus_attack import NostradamusAttack
from samson.primitives.merkle_damgard_construction import MerkleDamgardConstruction
from Crypto.Cipher import AES
from samson.utilities import gen_rand_key, stretch_key, int_to_bytes
from samson.primitives.aes_ecb import encrypt_aes_ecb
import struct
import unittest



def compressor(message, state):
    return encrypt_aes_ecb(stretch_key(state, 16), message)[:1]


def padder(message):
    return message


def construction_func(iv, message):
    return MerkleDamgardConstruction(iv, compressor, padder, output_size=8).yield_state(message)


class NostradamusAttackTestCase(unittest.TestCase):
    def test_nostradamus(self):
        attack = NostradamusAttack(k=3, construction_func=construction_func)
        del attack.hash_tree[b'S']
        new_message = attack.execute(b'z')

        # md = MerkleDamgardConstruction(b'z', compressor, padder, output_size=8)
        hashed_message = [state for state in construction_func(b'z', new_message[1:])][-1]
        self.assertEqual(hashed_message, attack.crafted_hash)