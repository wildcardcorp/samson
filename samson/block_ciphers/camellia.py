from samson.utilities.bytes import Bytes
from samson.utilities.manipulation import left_rotate

MASK8   = 0xFF
MASK32  = 0xFFFFFFFF
MASK64  = 0xFFFFFFFFFFFFFFFF
MASK128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

SIGMA1 = 0xA09E667F3BCC908B
SIGMA2 = 0xB67AE8584CAA73B2
SIGMA3 = 0xC6EF372FE94F82BE
SIGMA4 = 0x54FF53A5F1D36F1C
SIGMA5 = 0x10E527FADE682D1D
SIGMA6 = 0xB05688C2B3E6C1FD

SBOX = [
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
    35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
    134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
    166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
    139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
    223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
    20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
    254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
    16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
    135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
    82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
    120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
    64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158
]


def SBOX1(val):
    return SBOX[val]


def SBOX2(val):
    return left_rotate(SBOX[val], 1)


def SBOX3(val):
    return left_rotate(SBOX[val], 7)


def SBOX4(val):
    return SBOX[left_rotate(val, 7, bits=8)]


def ROTL128(x, amount):
    return left_rotate(x, amount, bits=128)


# https://tools.ietf.org/html/rfc3713
class Camellia(object):
    def __init__(self, key):
        key = Bytes.wrap(key)

        if not len(key) in [16, 24, 32]:
            raise ValueError("`key` must be 128, 192, or 256 bits long.")

        self.key = key
        self.k = []
        self.ke = []
        self.kw = [None] * 4

        self.key_schedule()

    
        
    def __repr__(self):
        return f"<Camellia: key={self.key}, key_len={len(self.key)}>"

    def __str__(self):
        return self.__repr__()
    

    def FL(self, FL_IN, KE):
        x1 = FL_IN >> 32
        x2 = FL_IN & MASK32
        self.k[0] = KE >> 32
        self.k[1] = KE & MASK32
        x2 = x2 ^ ROTL128((x1 & self.k[0]), 1)
        x1 = x1 ^ (x2 | self.k[1])
        return (x1 << 32) | x2


    def FLINV(self, FLINV_IN, KE):
        y1 = FLINV_IN >> 32
        y2 = FLINV_IN & MASK32
        self.k[0] = KE >> 32
        self.k[1] = KE & MASK32
        y1 = y1 ^ (y2 | self.k[1])
        y2 = y2 ^ ROTL128((y1 & self.k[0]), 1)
        return (y1 << 32) | y2


    def F(self, F_IN, KE):
        x  = (F_IN ^ KE) & MASK64
        t1 =  x >> 56
        t2 = (x >> 48) & MASK8
        t3 = (x >> 40) & MASK8
        t4 = (x >> 32) & MASK8
        t5 = (x >> 24) & MASK8
        t6 = (x >> 16) & MASK8
        t7 = (x >>  8) & MASK8
        t8 =  x        & MASK8
        t1 = SBOX1(t1)
        t2 = SBOX2(t2)
        t3 = SBOX3(t3)
        t4 = SBOX4(t4)
        t5 = SBOX2(t5)
        t6 = SBOX3(t6)
        t7 = SBOX4(t7)
        t8 = SBOX1(t8)
        y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
        y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
        y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
        y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
        y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
        y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
        y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
        y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
        return (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8



    def key_schedule(self):
        K = self.key.to_int()
        key_len = len(self.key)
        if key_len == 16:
            KL = K
            KR = 0
        elif key_len == 24:
            KL = K >> 64
            KR = ((K & MASK64) << 64) | (~(K & MASK64))
        else:
            KL = K >> 128
            KR = K & MASK128
        
        
        D1 = (KL ^ KR) >> 64
        D2 = (KL ^ KR) & MASK64
        D2 = D2 ^ self.F(D1, SIGMA1)
        D1 = D1 ^ self.F(D2, SIGMA2)
        D1 = D1 ^ (KL >> 64)
        D2 = D2 ^ (KL & MASK64)
        D2 = D2 ^ self.F(D1, SIGMA3)
        D1 = D1 ^ self.F(D2, SIGMA4)
        KA = (D1 << 64) | D2
        D1 = (KA ^ KR) >> 64
        D2 = (KA ^ KR) & MASK64
        D2 = D2 ^ self.F(D1, SIGMA5)
        D1 = D1 ^ self.F(D2, SIGMA6)
        KB = (D1 << 64) | D2

        if key_len == 16:
            self.k = [None] * 18
            self.ke = [None] * 4

            self.kw[0] = ROTL128(KL,   0) >> 64
            self.kw[1] = ROTL128(KL,   0) & MASK64
            self.k[0]  = ROTL128(KA,   0) >> 64
            self.k[1]  = ROTL128(KA,   0) & MASK64
            self.k[2]  = ROTL128(KL,  15) >> 64
            self.k[3]  = ROTL128(KL,  15) & MASK64
            self.k[4]  = ROTL128(KA,  15) >> 64
            self.k[5]  = ROTL128(KA,  15) & MASK64
            self.ke[0] = ROTL128(KA,  30) >> 64
            self.ke[1] = ROTL128(KA,  30) & MASK64
            self.k[6]  = ROTL128(KL,  45) >> 64
            self.k[7]  = ROTL128(KL,  45) & MASK64
            self.k[8]  = ROTL128(KA,  45) >> 64
            self.k[9]  = ROTL128(KL,  60) & MASK64
            self.k[10] = ROTL128(KA,  60) >> 64
            self.k[11] = ROTL128(KA,  60) & MASK64
            self.ke[2] = ROTL128(KL,  77) >> 64
            self.ke[3] = ROTL128(KL,  77) & MASK64
            self.k[12] = ROTL128(KL,  94) >> 64
            self.k[13] = ROTL128(KL,  94) & MASK64
            self.k[14] = ROTL128(KA,  94) >> 64
            self.k[15] = ROTL128(KA,  94) & MASK64
            self.k[16] = ROTL128(KL, 111) >> 64
            self.k[17] = ROTL128(KL, 111) & MASK64
            self.kw[2] = ROTL128(KA, 111) >> 64
            self.kw[3] = ROTL128(KA, 111) & MASK64
        else:
            self.k = [None] * 24
            self.ke = [None] * 6

            self.kw[0] = ROTL128(KL,   0) >> 64
            self.kw[1] = ROTL128(KL,   0) & MASK64
            self.k[0]  = ROTL128(KB,   0) >> 64
            self.k[1]  = ROTL128(KB,   0) & MASK64
            self.k[2]  = ROTL128(KR,  15) >> 64
            self.k[3]  = ROTL128(KR,  15) & MASK64
            self.k[4]  = ROTL128(KA,  15) >> 64
            self.k[5]  = ROTL128(KA,  15) & MASK64
            self.ke[0] = ROTL128(KR,  30) >> 64
            self.ke[1] = ROTL128(KR,  30) & MASK64
            self.k[6]  = ROTL128(KB,  30) >> 64
            self.k[7]  = ROTL128(KB,  30) & MASK64
            self.k[8]  = ROTL128(KL,  45) >> 64
            self.k[9]  = ROTL128(KL,  45) & MASK64
            self.k[10] = ROTL128(KA,  45) >> 64
            self.k[11] = ROTL128(KA,  45) & MASK64
            self.ke[2] = ROTL128(KL,  60) >> 64
            self.ke[3] = ROTL128(KL,  60) & MASK64
            self.k[12] = ROTL128(KR,  60) >> 64
            self.k[13] = ROTL128(KR,  60) & MASK64
            self.k[14] = ROTL128(KB,  60) >> 64
            self.k[15] = ROTL128(KB,  60) & MASK64
            self.k[16] = ROTL128(KL,  77) >> 64
            self.k[17] = ROTL128(KL,  77) & MASK64
            self.ke[4] = ROTL128(KA,  77) >> 64
            self.ke[5] = ROTL128(KA,  77) & MASK64
            self.k[18] = ROTL128(KR,  94) >> 64
            self.k[19] = ROTL128(KR,  94) & MASK64
            self.k[20] = ROTL128(KA,  94) >> 64
            self.k[21] = ROTL128(KA,  94) & MASK64
            self.k[22] = ROTL128(KL, 111) >> 64
            self.k[23] = ROTL128(KL, 111) & MASK64
            self.kw[2] = ROTL128(KB, 111) >> 64
            self.kw[3] = ROTL128(KB, 111) & MASK64



        
    def encrypt(self, plaintext):
        plaintext = Bytes.wrap(plaintext)
        M = plaintext.to_int()

        D1 = M >> 64
        D2 = M & MASK64

        D1 = D1 ^ self.kw[0]
        D2 = D2 ^ self.kw[1]

        # num_super_rounds = 3 if len(self.key) == 16 else 4


        # for i in range(num_super_rounds):
        #     for j in range(0, 6, 2):
        #         D2 ^= self.F(D1, self.k[i*6 + j])
        #         D1 ^= self.F(D2, self.k[i*6 + j +1])

        D2 = D2 ^ self.F(D1, self.k[0])
        D1 = D1 ^ self.F(D2, self.k[1])
        D2 = D2 ^ self.F(D1, self.k[2])
        D1 = D1 ^ self.F(D2, self.k[3])
        D2 = D2 ^ self.F(D1, self.k[4])
        D1 = D1 ^ self.F(D2, self.k[5])
        D1 = self.FL   (D1, self.ke[0])
        D2 = self.FLINV(D2, self.ke[1])
        D2 = D2 ^ self.F(D1, self.k[6])
        D1 = D1 ^ self.F(D2, self.k[7])
        D2 = D2 ^ self.F(D1, self.k[8])
        D1 = D1 ^ self.F(D2, self.k[9])
        D2 = D2 ^ self.F(D1, self.k[10])
        D1 = D1 ^ self.F(D2, self.k[11])
        D1 = self.FL   (D1, self.ke[2])
        D2 = self.FLINV(D2, self.ke[3])
        D2 = D2 ^ self.F(D1, self.k[12])
        D1 = D1 ^ self.F(D2, self.k[13])
        D2 = D2 ^ self.F(D1, self.k[14])
        D1 = D1 ^ self.F(D2, self.k[15])
        D2 = D2 ^ self.F(D1, self.k[16])
        D1 = D1 ^ self.F(D2, self.k[17])
        D1 = self.FL   (D1, self.ke[4])
        D2 = self.FLINV(D2, self.ke[5])
        D2 = D2 ^ self.F(D1, self.k[18])
        D1 = D1 ^ self.F(D2, self.k[19])
        D2 = D2 ^ self.F(D1, self.k[20])
        D1 = D1 ^ self.F(D2, self.k[21])
        D2 = D2 ^ self.F(D1, self.k[22])
        D1 = D1 ^ self.F(D2, self.k[23])


        D2 = D2 ^ self.kw[2]
        D1 = D1 ^ self.kw[3]

        return (D2 << 64) | D1