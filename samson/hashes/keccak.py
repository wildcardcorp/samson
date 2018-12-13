from math import log
from samson.utilities.bytes import Bytes
from samson.utilities.manipulation import left_rotate
from samson.constructions.sponge_construction import SpongeConstruction

# https://github.com/ctz/keccak/blob/master/keccak.py

RC = [
  0x0000000000000001,   0x0000000000008082,   0x800000000000808A,   0x8000000080008000,
  0x000000000000808B,   0x0000000080000001,   0x8000000080008081,   0x8000000000008009,
  0x000000000000008A,   0x0000000000000088,   0x0000000080008009,   0x000000008000000A,
  0x000000008000808B,   0x800000000000008B,   0x8000000000008089,   0x8000000000008003,
  0x8000000000008002,   0x8000000000000080,   0x000000000000800A,   0x800000008000000A,
  0x8000000080008081,   0x8000000000008080,   0x0000000080000001,   0x8000000080008008
]


R = [
  [  0,  1, 62, 28, 27, ],
  [ 36, 44,  6, 55, 20, ],
  [  3, 10, 43, 25, 39, ],
  [ 41, 45, 15, 21,  8, ],
  [ 18,  2, 61, 56, 14, ]
]

# https://keccak.team/keccak_specs_summary.html
class Keccak(SpongeConstruction):
    """
    SHA3 winner based on the SpongeConstruction.
    """

    def __init__(self, r: int, c: int, digest_bit_size: int, auto_reset_state: bool=True):
        """
        Parameters:
            r                 (int): Bit-size of the sponge function.
            c                 (int): Sponge capacity.
            digest_bit_size   (int): Desired size of output.
            auto_reset_state (bool): Whether or not to reset the internal state before hashing.
        """
        super().__init__(self.keccak_f, self.pad, r, c)
        self.w = (r + c) // 25

        self.n = int(log(self.w, 2) * 2 + 12)
        self.digest_size = (digest_bit_size // 8)
        self.auto_reset_state = auto_reset_state



    def __repr__(self):
        return f"<Keccak r={self.r}, c={self.c}, n={self.n}, w={self.w}, digest_size={self.digest_size}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    def pad(self, in_bytes: bytes) -> bytes:
        bit_rate_bytes = (self.r + 7) // 8
        pad_len = (bit_rate_bytes - len(in_bytes)) % bit_rate_bytes

        if pad_len == 0:
            pad_len = bit_rate_bytes

        if pad_len == 1:
            return in_bytes + bytes([0x81])
        else:
            return in_bytes + bytes([0x01] + ([0] * (pad_len - 2)) + [0x80])


    def keccak_f(self, A):
        for i in range(self.n):
            A = self.round_func(A, RC[i])
        return A


    def round_func(self, A, rc):
        C = [0] * 5
        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

        D = [0] * 5
        for x in range(5):
            D[x] = C[x-1] ^ left_rotate(C[(x+1) % 5], 1, 64)


        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y] ^ D[x]


        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2*x + 3*y) % 5] = left_rotate(A[x][y], R[y][x], 64)


        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x+1) % 5][y]) & B[(x+2) % 5][y])

        A[0][0] ^= rc

        return A



    def hash(self, message: bytes) -> Bytes:
        """
        Hashes the `message`.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            Bytes: The hash digest.
        """
        if self.auto_reset_state:
            self.reset()

        self.absorb(Bytes.wrap(message))
        return sum(self.squeeze(self.digest_size))[:self.digest_size]
