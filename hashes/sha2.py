from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction
from samson.constructions.davies_meyer_construction import DaviesMeyerConstruction
from samson.utilities.bytes import Bytes
from samson.utilities.padding import md_pad
from samson.utilities.manipulation import right_rotate, get_blocks
from copy import deepcopy

H_256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
H_224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]

k = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def compression_func(block, state):
    state = [int.from_bytes(chunk, 'big') for chunk in state.chunk(4)]
    w = [int.from_bytes(b, 'big') for b in get_blocks(block, 4)] + ([None] * 48)

    for i in range(16, 64):
        s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
    

    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]
    f = state[5]
    g = state[6]
    h = state[7]

    for i in range(64):
        S1 = right_rotate(e,  6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = g ^ (e & (f ^ g))
        temp1 = (h + S1 + ch + k[i] + w[i])
        S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj)

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF


    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h

    return Bytes(b''.join([int.to_bytes(h_i & 0xFFFFFFFF, 4, 'big') for h_i in state]))


def padding_func(message):
    return md_pad(message, None, 'big')


class SHA2(MerkleDamgardConstruction):
    def __init__(self , h=None, digest_size=256):
        if digest_size == 256:
            h_arr = H_256
        elif digest_size == 224:
            h_arr = H_224

        self.initial_state = h or Bytes(b''.join([int.to_bytes(h_i, 4, 'big') for h_i in h_arr]))
        self.compression_func = compression_func
        self.pad_func = padding_func
        self.block_size = 64
        self.digest_size = digest_size


    def yield_state(self, message):
        for state in MerkleDamgardConstruction.yield_state(self, message):
            if self.digest_size == 224:
                state = state[:-4]
            yield state
    

    def __repr__(self):
        return "<SHA2: initial_state={}, block_size={}, digest_size={}".format(self.initial_state, self.block_size, self.digest_size)