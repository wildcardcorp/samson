import struct
from copy import deepcopy
from samson.utilities.manipulation import left_rotate
from samson.utilities.padding import md_pad
from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction
from samson.hashes.md5 import state_to_bytes, bytes_to_state
from samson.utilities.bytes import Bytes


def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

iv = [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476
    ]



def compression_func(message, state):
    X = list( struct.unpack("<16I", message) + (None,) * (80-16) )
    #h = [x for x in bytes_to_state(state)]
    h = bytes_to_state(state)
    last_state = [x for x in h]

    # Round 1
    s = (3,7,11,19)
    for r in range(16):
        i = (16-r)%4
        k = r
        h[i] = left_rotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )


    # Round 2
    s = (3,5,9,13)
    for r in range(16):
        i = (16-r)%4
        k = 4*(r%4) + r//4
        h[i] = left_rotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )


    # Round 3
    s = (3,9,11,15)
    k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15)
    for r in range(16):
        i = (16-r)%4
        h[i] = left_rotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

    new_state = []
    for i,v in enumerate(h):
        new_state.append((v + last_state[i]) % 2**32)
    
    return Bytes(state_to_bytes(new_state))


    
def padding_func(message):
    return md_pad(message, None, 'little')



class MD4(MerkleDamgardConstruction):
    def __init__(self, internal_state=state_to_bytes(iv)):
        self.initial_state = deepcopy(internal_state)
        self.compression_func = compression_func
        self.pad_func = padding_func
        self.block_size = 64
        self.digest_size = 16


    def __repr__(self):
        return f"<MD4: initial_state={self.initial_state}, block_size={self.block_size}, pad_func={self.pad_func}>"


    def __str__(self):
        return self.__repr__()