from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction
from samson.utilities.manipulation import left_rotate
from samson.utilities.bytes import Bytes
import math

# https://rosettacode.org/wiki/MD5/Implementation#Python

rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + \
            16*[lambda b, c, d: (d & b) | (~d & c)] + \
            16*[lambda b, c, d: b ^ c ^ d] + \
            16*[lambda b, c, d: c ^ (b | ~d)]

index_functions = 16*[lambda i: i] + \
                  16*[lambda i: (5*i + 1)%16] + \
                  16*[lambda i: (3*i + 5)%16] + \
                  16*[lambda i: (7*i)%16]





def state_to_bytes(state):
    return int.to_bytes(sum(x<<(32*i) for i, x in enumerate(state)), 16, 'little')


def bytes_to_state(state_bytes):
    as_int = int.from_bytes(state_bytes, 'little')
    return [(as_int>>(32*i)) & 0xffffffff for i in range(4)]



def compression_func(message, state):
    new_state = bytes_to_state(state)

    for chunk_ofst in range(0, len(message), 64):
        a, b, c, d = new_state
        chunk = message[chunk_ofst:chunk_ofst+64]

        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g:4*g+4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c

        for i, val in enumerate([a, b, c, d]):
            new_state[i] += val
            new_state[i] &= 0xFFFFFFFF

    return Bytes(state_to_bytes(new_state))



class MD5(MerkleDamgardConstruction):
    """
    Popular but completely broken cryptographic hash function.
    """

    def __init__(self, initial_state: bytes=state_to_bytes([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476])):
        """
        Parameters:
            initial_state (bytes): (Optional) Initial internal state.
        """
        super().__init__(
            initial_state=initial_state,
            compression_func=compression_func,
            digest_size=16,
            endianness='little'
        )


    def __repr__(self):
        return f"<MD5: initial_state={self.initial_state}, block_size={self.block_size}>"


    def __str__(self):
        return self.__repr__()
