import math
from copy import deepcopy

import logging
log = logging.getLogger(__name__)


class NostradamusAttack(object):
    # 'k' is the number of levels the tree will have
    # `construction_func` takes in a message and POSSIBLY an IV and outputs a generator that yields the intermediary state

    # Example:
    # def construction_func(iv, message):
    #   return MerkleDamgardConstruction(iv, compressor, padder, output_size=hash_size).yield_state(message)

    def __init__(self, k, construction_func, output_size, prefixes=None):
        self.k = k
        self.prefixes = prefixes or [int.to_bytes(i, output_size, 'little') for i in range(2 ** k)]
        self.construction_func = construction_func
        self.output_size = output_size

        # Output fields
        self.hash_tree = {}
        self.crafted_hash = None

        self._generate_tree()


    @staticmethod
    def initialize_with_known_prefixes(prefixes, iv, construction_func, output_size):
        k = math.ceil(math.log(len(prefixes), 2))
        prefixes = [(prefix + (b'\x00' * output_size))[:output_size] for prefix in prefixes]
        hashed_prefixes = [[state for state in construction_func(iv, prefix)][0] for prefix in prefixes]

        return NostradamusAttack(k, construction_func, output_size, prefixes=hashed_prefixes)



    def _generate_tree(self):
        log.debug('Generating hash tree')
        tree = []
        for i in range(self.k):
            tree.append([])


        promoted_prefix = None

        # Determine if we need to "promote" a prefix. Basically, if we have an odd number of
        # prefixes on this layer, we put the last prefix in waiting as there will eventually be
        # another layer which has one less node than a power of two.
        curr_prefix_list = self.prefixes
        if len(self.prefixes) % 2 == 1:
            promoted_prefix = self.prefixes[-1]
            curr_prefix_list = self.prefixes[:-1]

        tree[0] = [(curr_prefix_list[i], curr_prefix_list[i + 1]) for i in range(0, len(curr_prefix_list), 2)]

        solution_tree = []
        for i in range(self.k):
            solution_tree.append([])


        for i in range(self.k):
            for (p1, p2) in tree[i]:
                input_for_p1 = b'\x00' * self.output_size
                state_to_collide = [state for state in self.construction_func(p1, input_for_p1)][0]

                # Try a lot of values...
                for j in range(2**(self.output_size * 32)):
                    attempt = int.to_bytes(j, self.output_size * 4, 'little')
                    found_collision = False

                    # We'll need to keep a state counter since we may not get a collision on the first chunk
                    state_ctr = 0

                    for state in self.construction_func(p2, attempt):
                        state_ctr += 1

                        if state == state_to_collide:
                            log.debug('Found collision for ({}, {})'.format(p1, p2))
                            found_collision = True
                            solution_tree[i].append((p1, p2, input_for_p1, attempt[:state_ctr * self.output_size], state_to_collide))
                            break

                    if found_collision:
                        break

            # Add solutions
            if i < (self.k - 1):

                # If there's an odd number of solutions at this level, then there's either a prefix
                # in waiting, or we need to promote one.
                next_level_states = solution_tree[i]
                if len(solution_tree[i]) % 2 == 1:
                    next_level_states = deepcopy(solution_tree[i])

                    # Last level is a multiple of 2 but not a power of 2 (e.g. 6).
                    # Promote our last prefix.
                    if promoted_prefix == None:
                        promoted_prefix = next_level_states[-1][-1]
                        next_level_states = next_level_states[:-1]

                    # We have a prefix in waiting. Use it immediately.
                    else:
                        next_level_states.append((promoted_prefix,))

                tree[i + 1] = [(next_level_states[sol][-1], next_level_states[sol + 1][-1]) for sol in range(0, len(next_level_states), 2)]

        # We're done generating the tree; time to set the output fields
        for layer in solution_tree:
            for p1_init, p2_init, p1_msg, p2_msg, result in layer:
                self.hash_tree[p1_init] = (p1_init, p2_init, p1_msg, p2_msg, result)
                self.hash_tree[p2_init] = (p1_init, p2_init, p1_msg, p2_msg, result)
        
        self.crafted_hash = solution_tree[-1][0][-1]



    def execute(self, message):
        suffix = b''

        while message in self.hash_tree:
            found_node = self.hash_tree[message]


            if found_node[0] == message:
                next_suffix = found_node[2]
            else:
                next_suffix = found_node[3]

            suffix += next_suffix
            message = found_node[-1]

        return suffix