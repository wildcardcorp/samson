from samson.utilities.manipulation import left_rotate, get_blocks
from samson.utilities.encoding import int_to_bytes
from copy import deepcopy
from math import ceil

# from samson.utilities
# https://en.wikipedia.org/wiki/Salsa20


def quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = left_rotate(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = left_rotate(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = left_rotate(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = left_rotate(b, 7)
    return a, b, c, d


class ChaCha(object):
    def __init__(self, key, nonce, rounds=20, constant=b"expand 32-byte k"):
        self.key = key
        self.nonce = nonce
        self.rounds = rounds
        self.constant = constant



    def yield_state(self, start_chunk=0, num_chunks=1):
        for iteration in range(start_chunk, num_chunks):
            ctr_bytes = int.to_bytes(iteration, 4, 'little')

            x = [
                *[int.from_bytes(block, 'little') for block in get_blocks(self.constant, 4)],
                *[int.from_bytes(block, 'little') for block in get_blocks(self.key, 4)],
                int.from_bytes(ctr_bytes, 'little'),
                *[int.from_bytes(block, 'little') for block in get_blocks(self.nonce, 4)]
            ]


            tmp = deepcopy(x)

            for _ in range(self.rounds // 2):
                # Odd round
                x[0], x[4], x[8], x[12] = quarter_round(x[0], x[4], x[8], x[12])
                x[1], x[5], x[9], x[13] = quarter_round(x[1], x[5], x[9], x[13])
                x[2], x[6], x[10], x[14] = quarter_round(x[2], x[6], x[10], x[14])
                x[3], x[7], x[11], x[15] = quarter_round(x[3], x[7], x[11], x[15])

                # Even round
                x[0], x[5], x[10], x[15] = quarter_round(x[0], x[5], x[10], x[15])
                x[1], x[6], x[11], x[12] = quarter_round(x[1], x[6], x[11], x[12])
                x[2], x[7], x[8], x[13] = quarter_round(x[2], x[7], x[8], x[13])
                x[3], x[4], x[9], x[14] = quarter_round(x[3], x[4], x[9], x[14])

            for i in range(16):
                x[i] += tmp[i]

            yield b''.join([int_to_bytes(state_int & 0xFFFFFFFF, 'little') for state_int in x])



assert(quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567) == (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb))
import codecs
chacha = ChaCha(key=b'\x00' * 32, nonce=b'\x00' * 12)
keystream_chunks = list(chacha.yield_state(0, 2))

assert codecs.encode(keystream_chunks[0], 'hex_codec') == b'76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
assert codecs.encode(keystream_chunks[1], 'hex_codec') == b'9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f'