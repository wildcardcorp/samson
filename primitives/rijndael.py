from samson.utilities.manipulation import left_rotate, stretch_key
from samson.utilities.bytes import Bytes


def initialize_sbox():
    p = 1
    q = 1

    sbox = [None] * 256
    first_round = True

    while first_round or p != 1:
        # Multiply p by 3
        p = p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)
        p &= 0xFF
        
        # Divide q by 3
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q ^= 0x09 if q & 0x80 else 0
        q &= 0xFF

        # Compute the affine transformation
        xformed = q ^ left_rotate(q, 1, 8) ^ left_rotate(q, 2, 8) ^ left_rotate(q, 3, 8) ^ left_rotate(q, 4, 8)
        xformed &= 0xFF

        sbox[p] = xformed ^ 0x63
        first_round = False

    # Zero has no inverse and must be set manually
    sbox[0] = 0x63

    return sbox



def invert_sbox(sbox):
    inv_sbox = [None] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i

    return inv_sbox


RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5]
SBOX = initialize_sbox()
INV_SBOX = invert_sbox(SBOX)
MIX_MATRIX = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]
INV_MIX_MATRIX = [14, 11, 13, 9, 9, 14, 11, 13, 13, 9, 14, 11, 11, 13, 9, 14]


class Rijndael(object):
    def __init__(self, key, block_size=128):
        if not (len(key) * 8) in range(128, 257, 32):
            raise Exception("Invalid key size! Must be between 128 and 256 and a multiple of 32")
        
        if not block_size in range(128, 257, 32):
            raise Exception("Invalid 'block_size'! Must be between 128 and 256 and a multiple of 32")

        
        self.key = Bytes.wrap(key)
        self.block_size = block_size

        round_keys = self.key_schedule()
        self.round_keys = [Bytes(b''.join(round_keys[i:i + 4])) for i in range(0, len(round_keys), 4)]


    # https://en.wikipedia.org/wiki/Rijndael_key_schedule
    def key_schedule(self):
        N = len(self.key) // 4
        K = list(self.key.chunk(4))
        R = max(N, self.block_size // 32) + 7

        W = []

        for i in range(4*R):
            if i < N:
                W_i = K[i]
            elif i % N == 0:
                W_i = W[i - N] ^ Bytes([SBOX[byte] for byte in W[i - 1].lrot(8)]) ^ bytes([RCON[i // N - 1], *[0] * 3])
            elif N > 6 and i % N == 4:
                W_i = W[i - N] ^ Bytes([SBOX[byte] for byte in W[i - 1]])
            else:
                W_i = W[i - N] ^ W[i - 1]

            W.append(W_i)

        return W


    def encrypt(self, plaintext):
        num_rounds = len(self.key) // 2 + 3
        state_matrix = Bytes.wrap(plaintext).transpose(4)
        
        for i in range(num_rounds):
            round_key = self.round_keys[i].transpose(4)
            if i == 0:
                state_matrix ^= round_key
            elif i < (num_rounds - 1):
                state_matrix = Bytes([SBOX[byte] for byte in state_matrix])
                state_matrix = self.shift_rows(state_matrix)
                state_matrix = Bytes(self.mix_columns(state_matrix, MIX_MATRIX))
                state_matrix ^= round_key
            else:
                state_matrix = Bytes([SBOX[byte] for byte in state_matrix])
                state_matrix = self.shift_rows(state_matrix)
                state_matrix ^= round_key
        
        return state_matrix


    def decrypt(self, ciphertext):
        num_rounds = len(self.key) // 2 + 3
        state_matrix = Bytes.wrap(ciphertext)

        reversed_round_keys = self.round_keys[::-1]

        for i in range(num_rounds):
            round_key = reversed_round_keys[i].transpose(4)
            if i == 0:
                state_matrix ^= round_key
            elif i < (num_rounds - 1):
                state_matrix = self.inv_shift_rows(state_matrix)
                state_matrix = Bytes([INV_SBOX[byte] for byte in state_matrix])
                state_matrix ^= round_key
                state_matrix = Bytes(self.mix_columns(state_matrix, INV_MIX_MATRIX))
            else:
                state_matrix = self.inv_shift_rows(state_matrix)
                state_matrix = Bytes([INV_SBOX[byte] for byte in state_matrix])
                state_matrix ^= round_key
        
        return state_matrix.transpose(4)



    def shift_rows(self, state_matrix):
        return b''.join([row.lrot(j * 8) for j, row in enumerate(state_matrix.chunk(4))])


    def inv_shift_rows(self, state_matrix):
        return b''.join([row.rrot(j * 8) for j, row in enumerate(state_matrix.chunk(4))])


    # https://en.wikipedia.org/wiki/Rijndael_MixColumns
    def _gmul(self, a, b):
        p = 0

        for _ in range(8):
            if (b & 1) != 0:
                p ^= a
            
            hi_bi_set = (a & 0x80) != 0
            a <<=1

            if hi_bi_set:
                a ^= 0x1B
            
            b >>= 1

        return p


    def mix_columns(self, state_matrix, mix_matrix):
        new_state = [None] * 16
        for c in range(4):
            new_state[c] = (self._gmul(mix_matrix[0], state_matrix[c]) ^ self._gmul(mix_matrix[1], state_matrix[c + 4]) ^ self._gmul(mix_matrix[2], state_matrix[c + 8]) ^ self._gmul(mix_matrix[3], state_matrix[c + 12])) & 0xFF
            new_state[c + 4] = (self._gmul(mix_matrix[4], state_matrix[c]) ^ self._gmul(mix_matrix[5], state_matrix[c + 4]) ^ self._gmul(mix_matrix[6], state_matrix[c + 8]) ^ self._gmul(mix_matrix[7], state_matrix[c + 12])) & 0xFF
            new_state[c + 8] = (self._gmul(mix_matrix[8], state_matrix[c]) ^ self._gmul(mix_matrix[9], state_matrix[c + 4]) ^ self._gmul(mix_matrix[10], state_matrix[c + 8]) ^ self._gmul(mix_matrix[11], state_matrix[c + 12])) & 0xFF
            new_state[c + 12] = (self._gmul(mix_matrix[12], state_matrix[c]) ^ self._gmul(mix_matrix[13], state_matrix[c + 4]) ^ self._gmul(mix_matrix[14], state_matrix[c + 8]) ^ self._gmul(mix_matrix[15], state_matrix[c + 12])) & 0xFF

            # new_state[c] = (self._gmul(2, state_matrix[c]) ^ self._gmul(3, state_matrix[c + 4]) ^ state_matrix[c + 8] ^ state_matrix[c + 12]) & 0xFF
            # new_state[c + 4] = (state_matrix[c] ^ self._gmul(2, state_matrix[c + 4]) ^ self._gmul(3, state_matrix[c + 8]) ^ state_matrix[c + 12]) & 0xFF
            # new_state[c + 8] = (state_matrix[c] ^ state_matrix[c + 4] ^ self._gmul(2, state_matrix[c + 8]) ^ self._gmul(3, state_matrix[c + 12])) & 0xFF
            # new_state[c + 12] = (self._gmul(3, state_matrix[c]) ^ state_matrix[c + 4] ^ state_matrix[c + 8] ^ self._gmul(2, state_matrix[c + 12])) & 0xFF

        return new_state



    # def inv_mix_columns(self, state_matrix):
    #     new_state = [None] * 16
    #     for c in range(4):
    #         new_state[c] = (self._gmul(14, state_matrix[c]) ^ self._gmul(11, state_matrix[c + 4]) ^ state_matrix[c + 8] ^ state_matrix[c + 12]) & 0xFF
    #         new_state[c + 4] = (state_matrix[c] ^ self._gmul(2, state_matrix[c + 4]) ^ self._gmul(3, state_matrix[c + 8]) ^ state_matrix[c + 12]) & 0xFF
    #         new_state[c + 8] = (state_matrix[c] ^ state_matrix[c + 4] ^ self._gmul(2, state_matrix[c + 8]) ^ self._gmul(3, state_matrix[c + 12])) & 0xFF
    #         new_state[c + 12] = (self._gmul(3, state_matrix[c]) ^ state_matrix[c + 4] ^ state_matrix[c + 8] ^ self._gmul(2, state_matrix[c + 12])) & 0xFF

    #     return new_state