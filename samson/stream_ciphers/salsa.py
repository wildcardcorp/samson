from samson.utilities.manipulation import left_rotate, get_blocks
from samson.utilities.bytes import Bytes
from copy import deepcopy

# https://en.wikipedia.org/wiki/Salsa20


def QUARTER_ROUND(a, b, c, d):
    b = (b ^ left_rotate((a + d) & 0xFFFFFFFF,  7))
    c = (c ^ left_rotate((b + a) & 0xFFFFFFFF,  9))
    d = (d ^ left_rotate((c + b) & 0xFFFFFFFF, 13))
    a = (a ^ left_rotate((d + c) & 0xFFFFFFFF, 18))
    return a, b, c, d


class Salsa(object):
    def __init__(self, key, nonce, rounds=20, constant=b"expand 32-byte k"):
        #self.key = Bytes.wrap(key).zfill(32)
        self.key = key
        self.nonce = nonce
        self.rounds = rounds
        self.constant = constant



    def __repr__(self):
        return f"<Salsa: key={self.key}, nonce={self.nonce}, rounds={self.rounds}, constant={self.constant}>"

    def __str__(self):
        return self.__repr__()



    def yield_state(self, start_chunk=0, num_chunks=1, state=None):
        for iteration in range(start_chunk, start_chunk + num_chunks):
            ctr_bytes = int.to_bytes(iteration, 8, 'little')

            cons_blocks  = [int.from_bytes(block, 'little') for block in get_blocks(self.constant, 4)]
            key_blocks   = [int.from_bytes(block, 'little') for block in get_blocks(self.key, 4)]
            ctr_blocks   = [int.from_bytes(block, 'little') for block in get_blocks(ctr_bytes, 4)]
            nonce_blocks = [int.from_bytes(block, 'little') for block in get_blocks(self.nonce, 4)]

            x = state or [
                cons_blocks[0],  *key_blocks[:4],
                cons_blocks[1],  *nonce_blocks,
                *ctr_blocks,     cons_blocks[2],
                *key_blocks[4:], cons_blocks[3]
            ]

            x = deepcopy(x)
            tmp = deepcopy(x)

            for _ in range(self.rounds // 2):
                # Odd round
                x[ 0], x[ 4], x[ 8], x[12] = QUARTER_ROUND(x[ 0], x[ 4], x[ 8], x[12])
                x[ 5], x[ 9], x[13], x[ 1] = QUARTER_ROUND(x[ 5], x[ 9], x[13], x[ 1])
                x[10], x[14], x[ 2], x[ 6] = QUARTER_ROUND(x[10], x[14], x[ 2], x[ 6])
                x[15], x[ 3], x[ 7], x[11] = QUARTER_ROUND(x[15], x[ 3], x[ 7], x[11])

                # Even round
                x[ 0], x[ 1], x[ 2], x[ 3] = QUARTER_ROUND(x[ 0], x[ 1], x[ 2], x[ 3])
                x[ 5], x[ 6], x[ 7], x[ 4] = QUARTER_ROUND(x[ 5], x[ 6], x[ 7], x[ 4])
                x[10], x[11], x[ 8], x[ 9] = QUARTER_ROUND(x[10], x[11], x[ 8], x[ 9])
                x[15], x[12], x[13], x[14] = QUARTER_ROUND(x[15], x[12], x[13], x[14])

            for i in range(16):
                x[i] += tmp[i]

            yield Bytes(b''.join([int.to_bytes(state_int & 0xFFFFFFFF, 4, 'little') for state_int in x]), byteorder='little')
