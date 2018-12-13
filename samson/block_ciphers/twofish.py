from samson.utilities.bytes import Bytes
from samson.utilities.encoding import poly_to_int, int_to_poly
from samson.utilities.manipulation import right_rotate, left_rotate

GF_MOD = 2**8 + 2**6 + 2**5 + 2**3 + 1
GF_MOD_POLY = int_to_poly(GF_MOD)

RS_MOD = 2**8 + 2**6 + 2**3 + 2**2 + 1
RS_MOD_POLY = int_to_poly(RS_MOD)

RHO = 0x01010101
ROUNDS = 16


MDS = [
    [ 0x01, 0xEF, 0x5B, 0x5B ],
    [ 0x5B, 0xEF, 0xEF, 0x01 ],
    [ 0xEF, 0x5B, 0x01, 0xEF ],
    [ 0xEF, 0x01, 0xEF, 0x5B ]
]

RS = [
    [ 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E ],
    [ 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5 ],
    [ 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19 ],
    [ 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03 ]
]

Q0 = [
    [ 0x8,0x1,0x7,0xD, 0x6,0xF,0x3,0x2, 0x0,0xB,0x5,0x9, 0xE,0xC,0xA,0x4 ],
    [ 0xE,0xC,0xB,0x8, 0x1,0x2,0x3,0x5, 0xF,0x4,0xA,0x6, 0x7,0x0,0x9,0xD ],
    [ 0xB,0xA,0x5,0xE, 0x6,0xD,0x9,0x0, 0xC,0x8,0xF,0x3, 0x2,0x4,0x7,0x1 ],
    [ 0xD,0x7,0xF,0x4, 0x1,0x2,0x6,0xE, 0x9,0xB,0x3,0x0, 0x8,0x5,0xC,0xA ]
]

Q1 = [
    [ 0x2,0x8,0xB,0xD, 0xF,0x7,0x6,0xE, 0x3,0x1,0x9,0x4, 0x0,0xA,0xC,0x5 ],
    [ 0x1,0xE,0x2,0xB, 0x4,0xC,0x3,0x7, 0x6,0xD,0xA,0x5, 0xF,0x9,0x0,0x8 ],
    [ 0x4,0xC,0x7,0x5, 0x1,0x6,0x9,0xA, 0x0,0xE,0xD,0x8, 0x2,0xB,0x3,0xF ],
    [ 0xB,0x9,0x5,0x1, 0xC,0x3,0xD,0xE, 0x6,0x4,0x7,0xF, 0x2,0x0,0x8,0xA ]
]

Q_BOXES = [Q0, Q1]


Q_ORD = [
    [ 1, 0, 1, 0 ],
    [ 0, 0, 1, 1 ],
    [ 0, 1, 0, 1 ],
    [ 1, 1, 0, 0 ],
    [ 1, 0, 0, 1 ]
]


def G(X, L, k):
    y = [_ for _ in Bytes(X).zfill(4)]

    for i in range(k - 1, -1, -1):
        for j in range(4):
            q_box = Q_BOXES[Q_ORD[i + 1][j]]
            y[j] = Q_PERMUTE(y[j], q_box) ^ L[i][j]


    for j in range(4):
        q_box = Q_BOXES[Q_ORD[0][j]]
        y[j] = Q_PERMUTE(y[j], q_box)


    z = MAT_MUL(MDS, y, GF_MOD_POLY)[::-1]
    return Bytes(z).int()



def PHT(a, b):
    return (a + b) % 2**32, (a + 2*b) % 2**32



def GF_MUL(a, b, poly_mod):
    poly_a = int_to_poly(a)
    poly_b = int_to_poly(b)
    return poly_to_int((poly_a * poly_b) % poly_mod)



def Q_PERMUTE(x, Q):
    a_0, b_0 = x // 16, x % 16
    a_1 = a_0 ^ b_0
    b_1 = (a_0 ^ right_rotate(b_0, 1, bits=4) ^ (a_0 * 8)) % 16

    a_2, b_2 = Q[0][a_1], Q[1][b_1]
    a_3 = a_2 ^ b_2
    b_3 = (a_2 ^ right_rotate(b_2, 1, bits=4) ^ (a_2 * 8)) % 16

    a_4, b_4 = Q[2][a_3], Q[3][b_3]
    return (b_4 * 16) + a_4



def MAT_MUL(mat, vec, mod):
    result = []
    for i in range(len(mat)):
        t = 0
        for j in range(len(vec)):
            t ^= GF_MUL(mat[i][j], vec[j], mod)

        result.append(t)

    return result


def EXPAND_KEY(M_e, M_o, k):
    K = []
    for i in range(ROUNDS + 4):
        A_i = G(2*i*RHO, M_e, k)
        B_i = G((2*i + 1) * RHO, M_o, k)
        B_i = left_rotate(B_i, 8)

        K.append((A_i + B_i) & 0xFFFFFFFF)
        K.append(left_rotate((A_i + 2*B_i) & 0xFFFFFFFF, 9))

    return K



# https://www.schneier.com/academic/paperfiles/paper-twofish-paper.pdf
class Twofish(object):
    """
    Structure: Feistel Network
    Key size: 128, 192, 256 bits
    Block size: 128 bits
    """

    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Bytes-like object to key the cipher.
        """
        self.key = Bytes.wrap(key)
        self.S = []
        self.K = None
        self.k = 0
        self._key_schedule()



    def __repr__(self):
        return f"<Twofish: key={self.key}, key_size={len(self.key) * 8}, S={self.S}, K={self.K}>"

    def __str__(self):
        return self.__repr__()



    def _key_schedule(self):
        M = self.key.chunk(4)
        self.k = k = len(M) // 2

        M_e = [M[i] for i in range(0, 2*k-1, 2)]
        M_o = [M[i] for i in range(1, 2*k,   2)]

        for i in range(k):
            vec = [byte for byte in M_e[i]] + [byte for byte in M_o[i]]
            self.S.append(MAT_MUL(RS, vec, RS_MOD_POLY))


        self.S.reverse()

        M_e_8 = [[_ for _ in chunk] for chunk in M_e]
        M_o_8 = [[_ for _ in chunk] for chunk in M_o]

        self.K = EXPAND_KEY(M_e_8, M_o_8, k)



    def F(self, R_0, R_1, i):
        R_0_little = int.from_bytes(int.to_bytes(R_0, 4, 'big'), 'little')
        R_1_little = int.from_bytes(int.to_bytes(left_rotate(R_1, 8), 4, 'big'), 'little')

        T_0 = G(R_0_little, self.S, self.k)
        T_1 = G(R_1_little, self.S, self.k)

        F_0 = (T_0 +   T_1 + self.K[2*i + 8]) & 0xFFFFFFFF
        F_1 = (T_0 + 2*T_1 + self.K[2*i + 9]) & 0xFFFFFFFF

        return F_0, F_1



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)
        pt_chunks = [chunk.zfill(4).int() for chunk in plaintext.chunk(4)]

        # Whitening
        R = [pt_chunks[i] ^ self.K[i] for i in range(len(pt_chunks))]

        for i in range(ROUNDS):
            FR_0, FR_1 = self.F(R[0], R[1], i)
            R = [
                R[0],
                R[1],
                right_rotate(R[2] ^ FR_0, 1),
                left_rotate(R[3], 1) ^ FR_1
            ]

            R[0], R[2] = R[2], R[0]
            R[1], R[3] = R[3], R[1]

        R = [R[(i+2) % 4] ^ self.K[i+4] for i in range(len(pt_chunks))]

        return Bytes(b''.join([int.to_bytes(r, 4, 'little') for r in R]))




    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)
        ct_chunks = [chunk.zfill(4)[::-1].int() for chunk in ciphertext.chunk(4)]

        # Dewhitening
        R = [ct_chunks[i] ^ self.K[i+4] for i in range(len(ct_chunks))]

        for i in range(ROUNDS -1, -1, -1):
            FR_0, FR_1 = self.F(R[0], R[1], i)
            R = [
                R[0],
                R[1],
                left_rotate(R[2], 1)  ^ FR_0,
                right_rotate(R[3] ^ FR_1, 1)
            ]

            R[0], R[2] = R[2], R[0]
            R[1], R[3] = R[3], R[1]

        R = [R[(i+2) % 4] ^ self.K[i] for i in range(len(ct_chunks))]

        return Bytes(b''.join([int.to_bytes(r, 4, 'little') for r in R]))
