from samson.utilities.manipulation import left_rotate, get_blocks
from samson.utilities.bytes import Bytes
from copy import deepcopy

# from samson.utilities
# https://en.wikipedia.org/wiki/Salsa20


def QUARTER_ROUND(a, b, c, d):
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


    def __repr__(self):
        return f"<ChaCha: key={self.key}, nonce={self.nonce}, rounds={self.rounds}, constant={self.constant}>"

    def __str__(self):
        return self.__repr__()



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
                x[0], x[4], x[ 8], x[12] = QUARTER_ROUND(x[0], x[4], x[ 8], x[12])
                x[1], x[5], x[ 9], x[13] = QUARTER_ROUND(x[1], x[5], x[ 9], x[13])
                x[2], x[6], x[10], x[14] = QUARTER_ROUND(x[2], x[6], x[10], x[14])
                x[3], x[7], x[11], x[15] = QUARTER_ROUND(x[3], x[7], x[11], x[15])

                # Even round
                x[0], x[5], x[10], x[15] = QUARTER_ROUND(x[0], x[5], x[10], x[15])
                x[1], x[6], x[11], x[12] = QUARTER_ROUND(x[1], x[6], x[11], x[12])
                x[2], x[7], x[ 8], x[13] = QUARTER_ROUND(x[2], x[7], x[ 8], x[13])
                x[3], x[4], x[ 9], x[14] = QUARTER_ROUND(x[3], x[4], x[ 9], x[14])

            for i in range(16):
                x[i] += tmp[i]

            yield Bytes(b''.join([int.to_bytes(state_int & 0xFFFFFFFF, 4, 'little') for state_int in x]), byteorder='little')