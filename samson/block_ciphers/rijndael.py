from samson.utilities.manipulation import left_rotate
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

SHIFT_ROW_OFFSETS = [
    *[[0, 1, 2, 3]] * 3,
    [0, 1, 2, 4],
    [0, 1, 3, 4]
]

NUM_ROUNDS = [
    [10, 12, 14],
    [12, 12, 14],
    [14, 14, 14]
]

# https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
class Rijndael(object):
    """
    Underlying cipher of AES.

    Structure: Substitution–permutation network
    Key size: 128, 160, 192, 224, 256 bits
    Block size: 128, 160, 192, 224, 256 bits
    """

    def __init__(self, key: bytes, block_size: int=16):
        """
        Parameters:
            key      (bytes): Bytes-like object to key the cipher.
            block_size (int): The desired block size in bytes.
        """
        key = Bytes.wrap(key)
        if not (len(key)) in range(16, 33, 4):
            raise Exception("Invalid key size! Must be between 128 bits (16 bytes) and 256 bits (32 bytes) and a multiple of 32 bits (4 bytes)")

        if not block_size in range(16, 33, 4):
            raise Exception("Invalid block size! Must be between 128 bits (16 bytes) and 256 bits (32 bytes) and a multiple of 32 bits (4 bytes)")


        self.key = key
        self.block_size = block_size

        self._chunk_size = self.block_size // 4
        round_keys = self.key_schedule()
        self.round_keys = [Bytes(b''.join(round_keys[i:i + self._chunk_size])) for i in range(0, len(round_keys), self._chunk_size)]

        Nk = len(self.key) // 4
        Nb = self._chunk_size
        self.num_rounds = NUM_ROUNDS[(Nk - 4) // 2][(Nb - 4) // 2] + 1


    def __repr__(self):
        return f"<Rijndael: key={self.key}, key_size={len(self.key)}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    # https://en.wikipedia.org/wiki/Rijndael_key_schedule
    def key_schedule(self):
        N = len(self.key) // 4
        K = self.key.chunk(4)
        R = max(N, self._chunk_size) + 7

        W = []

        for i in range(self._chunk_size*R):
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



    def yield_encrypt(self, plaintext):
        state_matrix = Bytes.wrap(plaintext).transpose(4)

        for i in range(self.num_rounds):
            round_key = self.round_keys[i].transpose(4)
            if i == 0:
                state_matrix ^= round_key
            elif i < (self.num_rounds - 1):
                state_matrix = Bytes([SBOX[byte] for byte in state_matrix])
                state_matrix = self.shift_rows(state_matrix)
                state_matrix = Bytes(self.mix_columns(state_matrix, MIX_MATRIX))
                state_matrix ^= round_key
            else:
                state_matrix = Bytes([SBOX[byte] for byte in state_matrix])
                state_matrix = self.shift_rows(state_matrix)
                state_matrix ^= round_key

            yield state_matrix.transpose(self._chunk_size)


    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        return list(self.yield_encrypt(plaintext))[-1]



    def yield_decrypt(self, ciphertext):
        state_matrix = Bytes.wrap(ciphertext).transpose(4)

        reversed_round_keys = self.round_keys[::-1]

        for i in range(self.num_rounds):
            round_key = reversed_round_keys[i].transpose(4)
            if i == 0:
                state_matrix ^= round_key
            elif i < (self.num_rounds - 1):
                state_matrix = self.inv_shift_rows(state_matrix)
                state_matrix = Bytes([INV_SBOX[byte] for byte in state_matrix])
                state_matrix ^= round_key
                state_matrix = Bytes(self.mix_columns(state_matrix, INV_MIX_MATRIX))
            else:
                state_matrix = self.inv_shift_rows(state_matrix)
                state_matrix = Bytes([INV_SBOX[byte] for byte in state_matrix])
                state_matrix ^= round_key

            yield state_matrix.transpose(self._chunk_size)



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        return list(self.yield_decrypt(ciphertext))[-1]


    def shift_rows(self, state_matrix):
        offsets = SHIFT_ROW_OFFSETS[(self._chunk_size) - 4]
        return b''.join([row.lrot(offsets[j] * 8) for j, row in enumerate(state_matrix.chunk(self._chunk_size))])


    def inv_shift_rows(self, state_matrix):
        offsets = SHIFT_ROW_OFFSETS[(self._chunk_size) - 4]
        return b''.join([row.rrot(offsets[j] * 8) for j, row in enumerate(state_matrix.chunk(self._chunk_size))])


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
        new_state = [None] * len(state_matrix)
        c0, c1, c2, c3 = [self._chunk_size * i for i in range(4)]

        for i in range(self._chunk_size):
            new_state[i + c0] = (self._gmul(mix_matrix[0], state_matrix[i + c0]) ^ self._gmul(mix_matrix[1], state_matrix[i + c1]) ^ self._gmul(mix_matrix[2], state_matrix[i + c2]) ^ self._gmul(mix_matrix[3], state_matrix[i + c3])) & 0xFF
            new_state[i + c1] = (self._gmul(mix_matrix[4], state_matrix[i + c0]) ^ self._gmul(mix_matrix[5], state_matrix[i + c1]) ^ self._gmul(mix_matrix[6], state_matrix[i + c2]) ^ self._gmul(mix_matrix[7], state_matrix[i + c3])) & 0xFF
            new_state[i + c2] = (self._gmul(mix_matrix[8], state_matrix[i + c0]) ^ self._gmul(mix_matrix[9], state_matrix[i + c1]) ^ self._gmul(mix_matrix[10], state_matrix[i + c2]) ^ self._gmul(mix_matrix[11], state_matrix[i + c3])) & 0xFF
            new_state[i + c3] = (self._gmul(mix_matrix[12], state_matrix[i + c0]) ^ self._gmul(mix_matrix[13], state_matrix[i + c1]) ^ self._gmul(mix_matrix[14], state_matrix[i + c2]) ^ self._gmul(mix_matrix[15], state_matrix[i + c3])) & 0xFF

        return new_state
