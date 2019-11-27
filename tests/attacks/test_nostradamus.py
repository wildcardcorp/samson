from samson.attacks.nostradamus_attack import NostradamusAttack
from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.manipulation import stretch_key
from samson.block_ciphers.modes.ecb import ECB

from samson.auxiliary.naive_collider import NaiveMDCollider
import unittest

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)


hash_size = 2
key_size = 16
block_size = 16


def compressor(message, state):
    return bytes(ECB(Rijndael(stretch_key(state, key_size))).encrypt(message)[:hash_size])


def padder(message):
    return message


def construction_func(iv, message):
    md = MerkleDamgardConstruction(iv, compressor, digest_size=block_size, block_size=hash_size)
    md.pad_func = padder
    return md.yield_state(message)


class NostradamusAttackTestCase(unittest.TestCase):
    def test_nostradamus(self):
        collider = NaiveMDCollider(construction_func=construction_func, output_size=hash_size)
        attack = NostradamusAttack(k=2, collision_func=collider.find_collision, output_size=hash_size)

        attempt_hash = [item for item in attack.hash_tree.items()][0][0]
        new_message = attack.execute(attempt_hash)

        hashed_message = list(construction_func( b'\x00' * 2, new_message))[-1]
        self.assertEqual(hashed_message, attack.crafted_hash)


    def test_chosen_prefix(self):
        prefixes = [b'Hiya', b'another', b'more']

        collider, k, prefixes, hashed_prefixes = NaiveMDCollider.initialize_with_known_prefixes(prefixes, b'\x00' * 2, construction_func=construction_func, output_size=hash_size)
        attack = NostradamusAttack(k, collider.find_collision, hash_size, hashed_prefixes)

        for i, prefix in enumerate(prefixes):
            orig_hash = hashed_prefixes[i]
            new_message = attack.execute(orig_hash)
            hashed_message = list(construction_func( b'\x00' * 2, prefix + new_message))[-1]
            self.assertEqual(hashed_message, attack.crafted_hash)
