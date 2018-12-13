import math
from types import FunctionType

import logging
log = logging.getLogger(__name__)


class NaiveMDCollider(object):
    """
    Merkle-Damgard collider that (naively) uses bruteforce to find collisions. Do not use for cryptographic
    strength algorithms.
    """

    def __init__(self, construction_func: FunctionType, output_size: int):
        """
        Parameters:
            construction_func (func): Function that takes in two bytes-like arguments
                                      and returns the next Merkle-Damgard state.

        Example:
        def construction_func(iv, message):
            return MerkleDamgardConstruction(iv, compressor, padder, output_size=hash_size).yield_state(message)


            output_size        (int): Size in bytes of the hash output.
        """
        self.construction_func = construction_func
        self.output_size = output_size



    @staticmethod
    def initialize_with_known_prefixes(prefixes: list, iv: bytes, construction_func: FunctionType, output_size: int):
        """
        Initializes a NaiveMDCollider using known prefixes. In Nostradamus-attack terms, the initial states
        you're trying to find collisions for.

        Parameters:
            prefixes          (list): List of bytes-like prefixes to build initial states from.
            iv               (bytes): Initial state of the Merkle-Damgard function (possibly None).
            construction_func (func): Function that takes in two bytes-like arguments
                                      and returns the next Merkle-Damgard state.
            output_size        (int): Size in bytes of the hash output.
        
        Returns:
            NaiveMDCollider: NaiveMDCollider initialized with known prefixes.
        """
        k = math.ceil(math.log(len(prefixes), 2))

        # Find the maximum length of padded prefixes
        padding_size = math.ceil(max([len(prefix) for prefix in prefixes]) / output_size) * output_size

        prefixes = [(prefix + (b'\x00' * padding_size))[:padding_size] for prefix in prefixes]
        hashed_prefixes = [list(construction_func(iv, prefix))[-1] for prefix in prefixes]

        return NaiveMDCollider(construction_func, output_size), k, prefixes, hashed_prefixes




    def find_collision(self, p1: bytes, p2: bytes) -> (bytes, bytes, bytes):
        """
        Finds a collision using bruteforce.

        Parameters:
            p1 (bytes): First sample.
            p2 (bytes): Second sample.
        
        Returns:
            (bytes, bytes, bytes): Tuple of bytes representing the collision as (p1_suffix, p2_suffix, self.hasher.hash(p1 + p1_suffix)).
        """
        input_for_p1 = b'\x00' * self.output_size
        state_to_collide = list(self.construction_func(p1, input_for_p1))[0]

        # Try a lot of values...
        for j in range(2**(self.output_size * 32)):
            attempt = int.to_bytes(j, self.output_size * 4, 'little')

            # We'll need to keep a state counter since we may not get a collision on the first chunk
            state_ctr = 0

            for state in self.construction_func(p2, attempt):
                state_ctr += 1

                if state == state_to_collide:
                    log.debug('Found collision for ({}, {})'.format(p1, p2))
                    return input_for_p1, attempt[:state_ctr * self.output_size], state_to_collide
