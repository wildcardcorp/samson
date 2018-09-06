
from math import log, ceil
from copy import deepcopy

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
        k = ceil(log(len(prefixes), 2))
        prefixes = [(prefix + (b'\x00' * output_size))[:output_size] for prefix in prefixes]
        hashed_prefixes = [[state for state in construction_func(iv, prefix)][0] for prefix in prefixes]

        return NostradamusAttack(k, construction_func, output_size, prefixes=hashed_prefixes)



    def _generate_tree(self):
        tree = []
        for i in range(self.k):
            tree.append([])

        tree[0] = [(self.prefixes[i], self.prefixes[i + 1]) for i in range(0, len(self.prefixes), 2)]

        solution_tree = []
        for i in range(self.k):
            solution_tree.append([])


        for i in range(self.k):
            for (p1, p2) in tree[i]:
                # print(p1, p2)
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
                            # print('Found collision')
                            found_collision = True
                            solution_tree[i].append((p1, p2, input_for_p1, attempt[:state_ctr * self.output_size], state_to_collide))
                            break

                    if found_collision:
                        break

            # Add solutions
            if i < (self.k - 1):
                #print(solution_tree)
                tree[i + 1] = [(solution_tree[i][sol][-1], solution_tree[i][sol + 1][-1]) for sol in range(0, 2 ** (self.k - i - 1), 2)]


        # We're done generating the tree; time to set the output fields
        for layer in solution_tree[:-1]:
            for sol, (p1_init, p2_init, p1_msg, p2_msg, result) in enumerate(layer):
                self.hash_tree[p1_init] = (p1_init, p2_init, p1_msg, p2_msg, result)
                self.hash_tree[p2_init] = (p1_init, p2_init, p1_msg, p2_msg, result)
                #self.hash_tree[result] = solution_tree[l + 1][sol // 2]
        
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