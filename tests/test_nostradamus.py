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
    return MerkleDamgardConstruction(iv, compressor, padder, block_size=hash_size).yield_state(message)


class NostradamusAttackTestCase(unittest.TestCase):
    def test_nostradamus(self):
        attack = NostradamusAttack(k=2, construction_func=construction_func, output_size=hash_size)
        attempt_hash = [item for item in attack.hash_tree.items()][0][0]
        new_message = attack.execute(attempt_hash)

        hashed_message = [state for state in construction_func( b'\x00' * 2, new_message)][-1]
        self.assertEqual(hashed_message, attack.crafted_hash)


    def test_chosen_prefix(self):
        prefixes = [b'Hiya', b'another', b'more']
        attack = NostradamusAttack.initialize_with_known_prefixes(prefixes, b'\x00' * 2, construction_func, hash_size)

        for prefix in prefixes:
            orig_hash = [state for state in construction_func( b'\x00' * 2, prefix[:2])][-1]
            new_message = attack.execute(orig_hash)
            hashed_message = [state for state in construction_func( b'\x00' * 2, prefix[:2] + new_message)][-1]
            self.assertEqual(hashed_message, attack.crafted_hash)