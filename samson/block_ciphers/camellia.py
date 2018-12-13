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


SBOX1 = [
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

SBOX2 = [
    224,   5,  88, 217, 103,  78, 129, 203, 201,  11, 174, 106, 213,  24,  93, 130,
    70, 223, 214,  39, 138,  50,  75,  66, 219,  28, 158, 156,  58, 202,  37, 123,
    13, 113,  95,  31, 248, 215,  62, 157, 124,  96, 185, 190, 188, 139,  22,  52,
    77, 195, 114, 149, 171, 142, 186, 122, 179,   2, 180, 173, 162, 172, 216, 154,
    23,  26,  53, 204, 247, 153,  97,  90, 232,  36,  86,  64, 225,  99,   9,  51,
    191, 152, 151, 133, 104, 252, 236,  10, 218, 111,  83,  98, 163,  46,   8, 175,
    40, 176, 116, 194, 189,  54,  34,  56, 100,  30,  57,  44, 166,  48, 229,  68,
    253, 136, 159, 101, 135, 107, 244,  35,  72,  16, 209,  81, 192, 249, 210, 160,
    85, 161,  65, 250,  67,  19, 196,  47, 168, 182,  60,  43, 193, 255, 200, 165,
    32, 137,   0, 144,  71, 239, 234, 183,  21,   6, 205, 181,  18, 126, 187,  41,
    15, 184,   7,   4, 155, 148,  33, 102, 230, 206, 237, 231,  59, 254, 127, 197,
    164,  55, 177,  76, 145, 110, 141, 118,   3,  45, 222, 150,  38, 125, 198,  92,
    211, 242,  79,  25,  63, 220, 121,  29,  82, 235, 243, 109,  94, 251, 105, 178,
    240,  49,  12, 212, 207, 140, 226, 117, 169,  74,  87, 132,  17,  69,  27, 245,
    228,  14, 115, 170, 241, 221,  89,  20, 108, 146,  84, 208, 120, 112, 227,  73,
    128,  80, 167, 246, 119, 147, 134, 131,  42, 199,  91, 233, 238, 143,   1,  61
]

SBOX3 = [
    56,  65,  22, 118, 217, 147,  96, 242, 114, 194, 171, 154, 117,   6,  87, 160,
    145, 247, 181, 201, 162, 140, 210, 144, 246,   7, 167,  39, 142, 178,  73, 222,
    67,  92, 215, 199,  62, 245, 143, 103,  31,  24, 110, 175,  47, 226, 133,  13,
    83, 240, 156, 101, 234, 163, 174, 158, 236, 128,  45, 107, 168,  43,  54, 166,
    197, 134,  77,  51, 253, 102,  88, 150,  58,   9, 149,  16, 120, 216,  66, 204,
    239,  38, 229,  97,  26,  63,  59, 130, 182, 219, 212, 152, 232, 139,   2, 235,
    10,  44,  29, 176, 111, 141, 136,  14,  25, 135,  78,  11, 169,  12, 121,  17,
    127,  34, 231,  89, 225, 218,  61, 200,  18,   4, 116,  84,  48, 126, 180,  40,
    85, 104,  80, 190, 208, 196,  49, 203,  42, 173,  15, 202, 112, 255,  50, 105,
    8,  98,   0,  36, 209, 251, 186, 237,  69, 129, 115, 109, 132, 159, 238,  74,
    195,  46, 193,   1, 230,  37,  72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
    41, 205, 108,  19, 100, 155,  99, 157, 192,  75, 183, 165, 137,  95, 177,  23,
    244, 188, 211,  70, 207,  55,  94,  71, 148, 250, 252,  91, 151, 254,  90, 172,
    60,  76,   3,  53, 243,  35, 184,  93, 106, 146, 213,  33,  68,  81, 198, 125,
    57, 131, 220, 170, 124, 119,  86,   5,  27, 164,  21,  52,  30,  28, 248,  82,
    32,  20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227,  64,  79
]


SBOX4 = [
    112,  44, 179, 192, 228,  87, 234, 174,  35, 107,  69, 165, 237,  79,  29, 146,
    134, 175, 124,  31,  62, 220,  94,  11, 166,  57, 213,  93, 217,  90,  81, 108,
    139, 154, 251, 176, 116,  43, 240, 132, 223, 203,  52, 118, 109, 169, 209,   4,
    20,  58, 222,  17,  50, 156,  83, 242, 254, 207, 195, 122,  36, 232,  96, 105,
    170, 160, 161,  98,  84,  30, 224, 100,  16,   0, 163, 117, 138, 230,   9, 221,
    135, 131, 205, 144, 115, 246, 157, 191,  82, 216, 200, 198, 129, 111,  19,  99,
    233, 167, 159, 188,  41, 249,  47, 180, 120,   6, 231, 113, 212, 171, 136, 141,
    114, 185, 248, 172,  54,  42,  60, 241,  64, 211, 187,  67,  21, 173, 119, 128,
    130, 236,  39, 229, 133,  53,  12,  65, 239, 147,  25,  33,  14,  78, 101, 189,
    184, 143, 235, 206,  48,  95, 197,  26, 225, 202,  71,  61,   1, 214,  86,  77,
    13, 102, 204,  45,  18,  32, 177, 153,  76, 194, 126,   5, 183,  49,  23, 215,
    88,  97,  27,  28,  15,  22,  24,  34,  68, 178, 181, 145,   8, 168, 252,  80,
    208, 125, 137, 151,  91, 149, 255, 210, 196,  72, 247, 219,   3, 218,  63, 148,
    92,   2,  74,  51, 103, 243, 127, 226, 155,  38,  55,  59, 150,  75, 190,  46,
    121, 140, 110, 142, 245, 182, 253,  89, 152, 106,  70, 186,  37,  66, 162, 250,
    7,  85, 238,  10,  73, 104,  56, 164,  40, 123, 201, 193, 227, 244, 199, 158
]


def FL(FL_IN, KE):
    x1 = (FL_IN >> 32) & MASK32
    x2 = FL_IN & MASK32
    k1 = (KE >> 32) & MASK32
    k2 = KE & MASK32

    x2 = x2 ^ left_rotate((x1 & k1), 1, bits=32)
    x1 = x1 ^ (x2 | k2)
    return (x1 << 32) | x2


def FLINV(FLINV_IN, KE):
    y1 = (FLINV_IN) >> 32 & MASK32
    y2 = FLINV_IN & MASK32
    k1 = (KE >> 32) & MASK32
    k2 = KE & MASK32

    y1 = y1 ^ (y2 | k2)
    y2 = y2 ^ left_rotate((y1 & k1), 1, bits=32)
    return (y1 << 32) | y2




def ROTL128(x, amount):
    return left_rotate(x, amount, bits=128)


# https://tools.ietf.org/html/rfc3713
# http://info.isl.ntt.co.jp/crypt/eng/camellia/dl/01espec.pdf
class Camellia(object):
    """
    Comparable to AES in Europe.

    Structure: Feistel Network
    Key size: 128, 192, 256
    Block size: 128
    """

    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Bytes-like object to key the cipher.
        """
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

        t1 = SBOX1[t1]
        t2 = SBOX2[t2]
        t3 = SBOX3[t3]
        t4 = SBOX4[t4]
        t5 = SBOX2[t5]
        t6 = SBOX3[t6]
        t7 = SBOX4[t7]
        t8 = SBOX1[t8]

        # `P` function
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
            KL = (K >> 64) & MASK128
            KR = ((K & MASK64) << 64) | (~K & MASK64)
        else:
            KL = (K >> 128) & MASK128
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




    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)
        M = plaintext.int()

        D1 = M >> 64
        D2 = M & MASK64

        D1 = D1 ^ self.kw[0]
        D2 = D2 ^ self.kw[1]

        num_super_rounds = 3 if len(self.key) == 16 else 4

        for i in range(num_super_rounds):
            if i > 0:
                D1 = FL   (D1, self.ke[(i-1) * 2])
                D2 = FLINV(D2, self.ke[(i-1) * 2 + 1])
            for j in range(0, 6, 2):
                D2 ^= self.F(D1, self.k[i*6 + j])
                D1 ^= self.F(D2, self.k[i*6 + j +1])


        D2 = D2 ^ self.kw[2]
        D1 = D1 ^ self.kw[3]

        return Bytes(((D2  & MASK64) << 64) | (D1 & MASK64)).zfill(16)



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)
        C = ciphertext.int()

        kw = [self.kw[2], self.kw[3], self.kw[0], self.kw[1]]
        ke = self.ke[::-1]
        k = self.k[::-1]

        D1 = C >> 64
        D2 = C & MASK64

        D1 = D1 ^ kw[0]
        D2 = D2 ^ kw[1]

        num_super_rounds = 3 if len(self.key) == 16 else 4

        for i in range(num_super_rounds):
            if i > 0:
                D1 = FL   (D1, ke[(i-1) * 2])
                D2 = FLINV(D2, ke[(i-1) * 2 + 1])
            for j in range(0, 6, 2):
                D2 ^= self.F(D1, k[i*6 + j])
                D1 ^= self.F(D2, k[i*6 + j +1])


        D2 = D2 ^ kw[2]
        D1 = D1 ^ kw[3]

        return Bytes(((D2  & MASK64) << 64) | (D1 & MASK64)).zfill(16)
