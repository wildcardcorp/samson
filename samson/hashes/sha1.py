#!/usr/bin/python3
# source: https://github.com/ajalt/python-sha1/blob/master/sha1.py
import io
import struct
from samson.utilities.manipulation import left_rotate
from samson.utilities.padding import md_pad
from samson.utilities.encoding import int_to_bytes
from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction

#h0, h1, h2, h3, h4
#_process_chunk
def compression_func(chunk, state):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64

    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i*4:i*4 + 4])[0]

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

    # Initialize hash value for this chunk
    h0, h1, h2, h3, h4 = bytes_to_state(state)

    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                        a, left_rotate(b, 30), c, d)

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    state = [h0, h1, h2, h3, h4]

    return state_to_bytes(state)



def state_to_bytes(state):
    return int_to_bytes(sum(x<<(32*i) for i, x in enumerate(state[::-1])), 'big')


def bytes_to_state(state_bytes):
    as_int = int.from_bytes(state_bytes, 'big')
    return [(as_int>>(32*i)) & 0xffffffff for i in range(4, -1, -1)]


    
def padding_func(message):
    return md_pad(message, None, 'big')


class SHA1(MerkleDamgardConstruction):
    def __init__(self, initial_state=None):
        self.initial_state = initial_state or state_to_bytes([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xC3D2E1F0])

        if type(self.initial_state) is list:
            self.initial_state = state_to_bytes(self.initial_state)

        self.compression_func = compression_func
        self.pad_func = padding_func
        self.block_size = 64


sha1 = SHA1()

assert(sha1.hash(b"The quick brown fox jumps over the lazy dog") ==
        bytes.fromhex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"))
assert(sha1.hash(b"The quick brown fox jumps over the lazy cog") ==
        bytes.fromhex("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"))
assert(sha1.hash(b"") ==
        bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709"))