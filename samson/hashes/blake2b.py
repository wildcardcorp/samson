from samson.utilities.manipulation import right_rotate
from samson.utilities.bytes import Bytes
from samson.hashes.sha2 import H_512

SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
]

# https://en.wikipedia.org/wiki/BLAKE_(hash_function)
def MIX(V_a, V_b, V_c, V_d, x, y):
    V_a = (V_a + V_b + x) & 0xFFFFFFFFFFFFFFFF
    V_d = right_rotate(V_d ^ V_a, 32, bits=64)

    V_c = (V_c + V_d) & 0xFFFFFFFFFFFFFFFF
    V_b = right_rotate(V_b ^ V_c, 24, bits=64)

    V_a = (V_a + V_b + y) & 0xFFFFFFFFFFFFFFFF
    V_d = right_rotate(V_d ^ V_a, 16, bits=64)

    V_c = (V_c + V_d) & 0xFFFFFFFFFFFFFFFF
    V_b = right_rotate(V_b ^ V_c, 63, bits=64)

    return V_a, V_b, V_c, V_d


def COMPRESS(h, iv, chunk, t, is_last_block):
    V = [None] * 16
    V[:8] = h
    V[8:] = iv

    V[12] ^= t & 0xFFFFFFFFFFFFFFFF
    V[13] ^= t >> 64

    if is_last_block:
        V[14] ^= 0xFFFFFFFFFFFFFFFF

    m = [m_i.to_int() for m_i in chunk.chunk(8)]

    for i in range(12):
        S = [None] * 16
        S = SIGMA[i % 10]

        V[0], V[4], V[8], V[12] = MIX(V[0], V[4], V[8], V[12], m[S[0]], m[S[1]])
        V[1], V[5], V[9], V[13] = MIX(V[1], V[5], V[9], V[13], m[S[2]], m[S[3]])
        V[2], V[6], V[10], V[14] = MIX(V[2], V[6], V[10], V[14], m[S[4]], m[S[5]])
        V[3], V[7], V[11], V[15] = MIX(V[3], V[7], V[11], V[15], m[S[6]], m[S[7]])


        V[0], V[5], V[10], V[15] = MIX(V[0], V[5], V[10], V[15], m[S[8]], m[S[9]])
        V[1], V[6], V[11], V[12] = MIX(V[1], V[6], V[11], V[12], m[S[10]], m[S[11]])
        V[2], V[7], V[8], V[13] = MIX(V[2], V[7], V[8], V[13], m[S[12]], m[S[13]])
        V[3], V[4], V[9], V[14] = MIX(V[3], V[4], V[9], V[14], m[S[14]], m[S[15]])
    
    h = [x ^ y for x, y in zip(h, V[:8])]
    h = [x ^ y for x, y in zip(h, V[8:])]

    return h


    
from samson.utilities.padding import md_pad
from copy import deepcopy

def padding_func(message):
    if len(message) % 128 != 0 or len(message) == 0:
        message = message + b'\x00' * (128 - (len(message) % 128))
    return message

class BLAKE2b(object):
    def __init__(self, desired_hash_len=64, key=b'', iv=H_512):
        self.iv = iv
        self.padding_func = padding_func
        self.key = key
        self.desired_hash_len = desired_hash_len


    def __repr__(self):
        return f"<BLAKE2b: iv={self.iv}, desired_hash_len={self.desired_hash_len}, padding_func={self.padding_func}, key={self.key}>"


    def __str__(self):
        return self.__repr__()


    def hash(self, message):
        message = Bytes(message, 'little')
        state = deepcopy(self.iv)

        last_block_size = len(message) % 128

        if last_block_size == 0 and len(message) > 0:
            last_block_size = 128

        state[0] ^= (0x0101 << 16) + (len(self.key) << 8) + (self.desired_hash_len)

        if len(self.key) > 0:
            message = self.padding_func(self.key) + message

        padded_msg = self.padding_func(message)
        bytes_compressed = 0

        msg_chunks = padded_msg.chunk(128)

        for i, chunk in enumerate(msg_chunks):
            is_last_block = i == (len(msg_chunks) - 1)
            bytes_compressed += last_block_size if is_last_block else 128
            state = COMPRESS(state, self.iv, chunk, bytes_compressed, is_last_block)
            

        return sum([Bytes(h, byteorder='little').zfill(8) for h in state])[:self.desired_hash_len]