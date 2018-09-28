from math import log
from samson.utilities.bytes import Bytes

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
class Keccak(object):
    def __init__(self, r, c):
        self.r = r
        self.c = c
        self.w = (r + c) // 25

        self.n = log(self.w, 2) * 2 + 12


    def keccak_f(self, A):
        for i in range(self.n):
            A = self.round_func(A, RC[i])
        return A


    def round_func(self, A, rc):
        C = Bytes(b'\x00' * 4)
        for x in range(4):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

        D = Bytes(b'\x00' * 4)
        for x in range(4):
            D[x] = C[x-1] ^ C[x+1].rrot(1)


        for x in range(4):
            for y in range(4):
                A[x][y] = A[x][y] ^ D[x]

        B = Bytes(b'\x00' * 16)
        for x in range(4):
            for y in range(4):
                B[y][2*x + 3*y] = A[x][y].rrot(R[x][y])


        for x in range(4):
            for y in range(4):
                A[x][y] = B[x][y] ^ ((~B[x+1, y]) & B[x+2, y])

        A[0][0] ^= rc

        return A