from samson.primitives.merkle_damgard_construction import MerkleDamgardConstruction
from Crypto.Cipher import AES
from samson.utilities import gen_rand_key, stretch_key, int_to_bytes
from samson.primitives.aes_ecb import encrypt_aes_ecb
import struct


def compressor(message, state):
    return encrypt_aes_ecb(stretch_key(state, 16), message)[:1]
    #return AES.new(key, AES.MODE_ECB).encrypt(message)


def padder(message):
    return message

class NostradamusAttack(object):
    # 'k' is the number of levels the tree will have
    # `construction_func` takes in an IV and message and outputs a generator that yields the intermediary state
    def __init__(self, k, construction_func):
        self.k = k
        self.construction_func = construction_func

        # Output fields
        self.hash_tree = {}
        self.crafted_hash = None
        
        self._generate_tree()


    def _generate_tree(self):
        tree = [[(struct.pack('B', i), struct.pack('B', i + 1)) for i in range(0, 2**self.k, 2)]] + [[]] * self.k
        solution_tree = []
        for i in range(self.k):
            solution_tree.append([])


        for i in range(self.k):
            for (p1, p2) in tree[i]:
                # md1 = MerkleDamgardConstruction(p1, compressor, padder, output_size=8)
                # md2 = MerkleDamgardConstruction(p2, compressor, padder, output_size=8)
                # state_to_collide = [state for state in md1.yield_state(b'\x00')][0]
                state_to_collide = [state for state in self.construction_func(p1, b'\x00')][0]
                print(state_to_collide)
                for j in range(2**10):
                    attempt = struct.pack('Q', j)
                    found_collision = False
                    byte_ctr = 0
                    # for state in md2.yield_state(attempt):
                    for state in self.construction_func(p2, attempt):
                        byte_ctr += 1
                        if state == state_to_collide:
                            print('Found collision')
                            found_collision = True
                            solution_tree[i].append((p1, p2, b'\x00', attempt[  :byte_ctr], state_to_collide))
                            break
                    if found_collision:
                        break
            if i < (self.k - 1):
                tree[i + 1] = [(solution_tree[i][sol][-1], solution_tree[i][sol + 1][-1]) for sol in range(0, 2 ** (self.k - i - 1), 2)]

        for l, layer in enumerate(solution_tree[:-1]):
            for sol, (p1_init, p2_init, p1_msg, p2_msg, result) in enumerate(layer):
                self.hash_tree[result] = solution_tree[l + 1][sol // 2]
        
        self.crafted_hash = solution_tree[-1][0][-1]


    def execute(self, message):
        suffix = message

        while message in self.hash_tree:
            found_node = self.hash_tree[message]


            if found_node[0] == message:
                next_suffix = found_node[2]
            else:
                next_suffix = found_node[3]

            suffix += next_suffix
            message = found_node[-1]

        return suffix