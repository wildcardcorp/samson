import math

import logging
log = logging.getLogger(__name__)


class NaiveMDCollider(object):
    def __init__(self, construction_func, output_size):
        self.construction_func = construction_func
        self.output_size = output_size


    
    @staticmethod
    def initialize_with_known_prefixes(prefixes, iv, construction_func, output_size):
        k = math.ceil(math.log(len(prefixes), 2))

        # Find the maximum length of padded prefixes
        padding_size = math.ceil(max([len(prefix) for prefix in prefixes]) / output_size) * output_size

        prefixes = [(prefix + (b'\x00' * padding_size))[:padding_size] for prefix in prefixes]
        hashed_prefixes = [list(construction_func(iv, prefix))[-1] for prefix in prefixes]

        return NaiveMDCollider(construction_func, output_size), k, prefixes, hashed_prefixes




    def find_collision(self, p1, p2):
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
