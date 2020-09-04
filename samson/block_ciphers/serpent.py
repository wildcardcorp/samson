from samson.utilities.bytes import Bytes
from samson.utilities.manipulation import left_rotate
from samson.utilities.bitstring import Bitstring
from samson.core.primitives import BlockCipher, Primitive
from samson.core.metadata import ConstructionType
from samson.ace.decorators import register_primitive

# https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
# https://www.cl.cam.ac.uk/~fms27/serpent/serpent.py.html

IP_TABLE = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
]

FP_TABLE = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
]

LT_TABLE = [
    [16, 52, 56, 70, 83, 94, 105],
    [72, 114, 125],
    [2, 9, 15, 30, 76, 84, 126],
    [36, 90, 103],
    [20, 56, 60, 74, 87, 98, 109],
    [1, 76, 118],
    [2, 6, 13, 19, 34, 80, 88],
    [40, 94, 107],
    [24, 60, 64, 78, 91, 102, 113],
    [5, 80, 122],
    [6, 10, 17, 23, 38, 84, 92],
    [44, 98, 111],
    [28, 64, 68, 82, 95, 106, 117],
    [9, 84, 126],
    [10, 14, 21, 27, 42, 88, 96],
    [48, 102, 115],
    [32, 68, 72, 86, 99, 110, 121],
    [2, 13, 88],
    [14, 18, 25, 31, 46, 92, 100],
    [52, 106, 119],
    [36, 72, 76, 90, 103, 114, 125],
    [6, 17, 92],
    [18, 22, 29, 35, 50, 96, 104],
    [56, 110, 123],
    [1, 40, 76, 80, 94, 107, 118],
    [10, 21, 96],
    [22, 26, 33, 39, 54, 100, 108],
    [60, 114, 127],
    [5, 44, 80, 84, 98, 111, 122],
    [14, 25, 100],
    [26, 30, 37, 43, 58, 104, 112],
    [3, 118],
    [9, 48, 84, 88, 102, 115, 126],
    [18, 29, 104],
    [30, 34, 41, 47, 62, 108, 116],
    [7, 122],
    [2, 13, 52, 88, 92, 106, 119],
    [22, 33, 108],
    [34, 38, 45, 51, 66, 112, 120],
    [11, 126],
    [6, 17, 56, 92, 96, 110, 123],
    [26, 37, 112],
    [38, 42, 49, 55, 70, 116, 124],
    [2, 15, 76],
    [10, 21, 60, 96, 100, 114, 127],
    [30, 41, 116],
    [0, 42, 46, 53, 59, 74, 120],
    [6, 19, 80],
    [3, 14, 25, 100, 104, 118],
    [34, 45, 120],
    [4, 46, 50, 57, 63, 78, 124],
    [10, 23, 84],
    [7, 18, 29, 104, 108, 122],
    [38, 49, 124],
    [0, 8, 50, 54, 61, 67, 82],
    [14, 27, 88],
    [11, 22, 33, 108, 112, 126],
    [0, 42, 53],
    [4, 12, 54, 58, 65, 71, 86],
    [18, 31, 92],
    [2, 15, 26, 37, 76, 112, 116],
    [4, 46, 57],
    [8, 16, 58, 62, 69, 75, 90],
    [22, 35, 96],
    [6, 19, 30, 41, 80, 116, 120],
    [8, 50, 61],
    [12, 20, 62, 66, 73, 79, 94],
    [26, 39, 100],
    [10, 23, 34, 45, 84, 120, 124],
    [12, 54, 65],
    [16, 24, 66, 70, 77, 83, 98],
    [30, 43, 104],
    [0, 14, 27, 38, 49, 88, 124],
    [16, 58, 69],
    [20, 28, 70, 74, 81, 87, 102],
    [34, 47, 108],
    [0, 4, 18, 31, 42, 53, 92],
    [20, 62, 73],
    [24, 32, 74, 78, 85, 91, 106],
    [38, 51, 112],
    [4, 8, 22, 35, 46, 57, 96],
    [24, 66, 77],
    [28, 36, 78, 82, 89, 95, 110],
    [42, 55, 116],
    [8, 12, 26, 39, 50, 61, 100],
    [28, 70, 81],
    [32, 40, 82, 86, 93, 99, 114],
    [46, 59, 120],
    [12, 16, 30, 43, 54, 65, 104],
    [32, 74, 85],
    [36, 90, 103, 118],
    [50, 63, 124],
    [16, 20, 34, 47, 58, 69, 108],
    [36, 78, 89],
    [40, 94, 107, 122],
    [0, 54, 67],
    [20, 24, 38, 51, 62, 73, 112],
    [40, 82, 93],
    [44, 98, 111, 126],
    [4, 58, 71],
    [24, 28, 42, 55, 66, 77, 116],
    [44, 86, 97],
    [2, 48, 102, 115],
    [8, 62, 75],
    [28, 32, 46, 59, 70, 81, 120],
    [48, 90, 101],
    [6, 52, 106, 119],
    [12, 66, 79],
    [32, 36, 50, 63, 74, 85, 124],
    [52, 94, 105],
    [10, 56, 110, 123],
    [16, 70, 83],
    [0, 36, 40, 54, 67, 78, 89],
    [56, 98, 109],
    [14, 60, 114, 127],
    [20, 74, 87],
    [4, 40, 44, 58, 71, 82, 93],
    [60, 102, 113],
    [3, 18, 72, 114, 118, 125],
    [24, 78, 91],
    [8, 44, 48, 62, 75, 86, 97],
    [64, 106, 117],
    [1, 7, 22, 76, 118, 122],
    [28, 82, 95],
    [12, 48, 52, 66, 79, 90, 101],
    [68, 110, 121],
    [5, 11, 26, 80, 122, 126],
    [32, 86, 99],
    ]

# The following table is necessary for the non-bitslice decryption.
LT_TABLE_INV = [
    [53, 55, 72],
    [1, 5, 20, 90],
    [15, 102],
    [3, 31, 90],
    [57, 59, 76],
    [5, 9, 24, 94],
    [19, 106],
    [7, 35, 94],
    [61, 63, 80],
    [9, 13, 28, 98],
    [23, 110],
    [11, 39, 98],
    [65, 67, 84],
    [13, 17, 32, 102],
    [27, 114],
    [1, 3, 15, 20, 43, 102],
    [69, 71, 88],
    [17, 21, 36, 106],
    [1, 31, 118],
    [5, 7, 19, 24, 47, 106],
    [73, 75, 92],
    [21, 25, 40, 110],
    [5, 35, 122],
    [9, 11, 23, 28, 51, 110],
    [77, 79, 96],
    [25, 29, 44, 114],
    [9, 39, 126],
    [13, 15, 27, 32, 55, 114],
    [81, 83, 100],
    [1, 29, 33, 48, 118],
    [2, 13, 43],
    [1, 17, 19, 31, 36, 59, 118],
    [85, 87, 104],
    [5, 33, 37, 52, 122],
    [6, 17, 47],
    [5, 21, 23, 35, 40, 63, 122],
    [89, 91, 108],
    [9, 37, 41, 56, 126],
    [10, 21, 51],
    [9, 25, 27, 39, 44, 67, 126],
    [93, 95, 112],
    [2, 13, 41, 45, 60],
    [14, 25, 55],
    [2, 13, 29, 31, 43, 48, 71],
    [97, 99, 116],
    [6, 17, 45, 49, 64],
    [18, 29, 59],
    [6, 17, 33, 35, 47, 52, 75],
    [101, 103, 120],
    [10, 21, 49, 53, 68],
    [22, 33, 63],
    [10, 21, 37, 39, 51, 56, 79],
    [105, 107, 124],
    [14, 25, 53, 57, 72],
    [26, 37, 67],
    [14, 25, 41, 43, 55, 60, 83],
    [0, 109, 111],
    [18, 29, 57, 61, 76],
    [30, 41, 71],
    [18, 29, 45, 47, 59, 64, 87],
    [4, 113, 115],
    [22, 33, 61, 65, 80],
    [34, 45, 75],
    [22, 33, 49, 51, 63, 68, 91],
    [8, 117, 119],
    [26, 37, 65, 69, 84],
    [38, 49, 79],
    [26, 37, 53, 55, 67, 72, 95],
    [12, 121, 123],
    [30, 41, 69, 73, 88],
    [42, 53, 83],
    [30, 41, 57, 59, 71, 76, 99],
    [16, 125, 127],
    [34, 45, 73, 77, 92],
    [46, 57, 87],
    [34, 45, 61, 63, 75, 80, 103],
    [1, 3, 20],
    [38, 49, 77, 81, 96],
    [50, 61, 91],
    [38, 49, 65, 67, 79, 84, 107],
    [5, 7, 24],
    [42, 53, 81, 85, 100],
    [54, 65, 95],
    [42, 53, 69, 71, 83, 88, 111],
    [9, 11, 28],
    [46, 57, 85, 89, 104],
    [58, 69, 99],
    [46, 57, 73, 75, 87, 92, 115],
    [13, 15, 32],
    [50, 61, 89, 93, 108],
    [62, 73, 103],
    [50, 61, 77, 79, 91, 96, 119],
    [17, 19, 36],
    [54, 65, 93, 97, 112],
    [66, 77, 107],
    [54, 65, 81, 83, 95, 100, 123],
    [21, 23, 40],
    [58, 69, 97, 101, 116],
    [70, 81, 111],
    [58, 69, 85, 87, 99, 104, 127],
    [25, 27, 44],
    [62, 73, 101, 105, 120],
    [74, 85, 115],
    [3, 62, 73, 89, 91, 103, 108],
    [29, 31, 48],
    [66, 77, 105, 109, 124],
    [78, 89, 119],
    [7, 66, 77, 93, 95, 107, 112],
    [33, 35, 52],
    [0, 70, 81, 109, 113],
    [82, 93, 123],
    [11, 70, 81, 97, 99, 111, 116],
    [37, 39, 56],
    [4, 74, 85, 113, 117],
    [86, 97, 127],
    [15, 74, 85, 101, 103, 115, 120],
    [41, 43, 60],
    [8, 78, 89, 117, 121],
    [3, 90],
    [19, 78, 89, 105, 107, 119, 124],
    [45, 47, 64],
    [12, 82, 93, 121, 125],
    [7, 94],
    [0, 23, 82, 93, 109, 111, 123],
    [49, 51, 68],
    [1, 16, 86, 97, 125],
    [11, 98],
    [4, 27, 86, 97, 113, 115, 127],
]


SBOX = [{'0110': '1010', '0111': '1001', '0000': '1100', '0001': '0111', '0011': '1110', '0010': '0101', '0101': '0010', '0100': '1111', '1111': '0011', '1110': '1101', '1100': '1000', '1101': '0100', '1010': '0110', '1011': '0000', '1001': '1011', '1000': '0001'}, {'0110': '1010', '0111': '1100', '0000': '1111', '0001': '1000', '0011': '0110', '0010': '1001', '0101': '0111', '0100': '0100', '1111': '0010', '1110': '0101', '1100': '1110', '1101': '0001', '1010': '0000', '1011': '1011', '1001': '1101', '1000': '0011'}, {'0110': '0101', '0111': '1010', '0000': '0001', '0001': '1011', '0011': '0000', '0010': '1100', '0101': '0111', '0100': '1110', '1111': '0100', '1110': '1111', '1100': '1001', '1101': '0010', '1010': '0011', '1011': '1101', '1001': '1000', '1000': '0110'}, {'0110': '0110', '0111': '1010', '0000': '0000', '0001': '1011', '0011': '0101', '0010': '0011', '0101': '0100', '0100': '1101', '1111': '0111', '1110': '1100', '1100': '0001', '1101': '0010', '1010': '1001', '1011': '1110', '1001': '1000', '1000': '1111'}, {'0110': '1101', '0111': '1110', '0000': '1000', '0001': '0100', '0011': '1001', '0010': '0011', '0101': '0010', '0100': '0001', '1111': '1011', '1110': '0110', '1100': '1100', '1101': '0101', '1010': '0000', '1011': '0111', '1001': '1010', '1000': '1111'}, {'0110': '1001', '0111': '1110', '0000': '1111', '0001': '0000', '0011': '1011', '0010': '0010', '0101': '0111', '0100': '0100', '1111': '1000', '1110': '0011', '1100': '1101', '1101': '0001', '1010': '0101', '1011': '0110', '1001': '1100', '1000': '1010'}, {'0110': '0110', '0111': '0101', '0000': '1110', '0001': '0111', '0011': '1011', '0010': '0001', '0101': '1000', '0100': '0011', '1111': '0000', '1110': '1101', '1100': '1010', '1101': '1111', '1010': '0010', '1011': '1100', '1001': '1001', '1000': '0100'}, {'0110': '0100', '0111': '1010', '0000': '1000', '0001': '1110', '0011': '1001', '0010': '0111', '0101': '0011', '0100': '1111', '1111': '0110', '1110': '1101', '1100': '0000', '1101': '0101', '1010': '0001', '1011': '1100', '1001': '0010', '1000': '1011'}]
SBOX_INV = [{'0110': '1010', '0111': '0001', '0000': '1011', '0001': '1000', '0011': '1111', '0010': '0101', '0101': '0010', '0100': '1101', '1111': '0100', '1110': '0011', '1100': '0000', '1101': '1110', '1010': '0110', '1011': '1001', '1001': '0111', '1000': '1100'}, {'0110': '0011', '0111': '0101', '0000': '1010', '0001': '1101', '0011': '1000', '0010': '1111', '0101': '1110', '0100': '0100', '1111': '0000', '1110': '1100', '1100': '0111', '1101': '1001', '1010': '0110', '1011': '1011', '1001': '0010', '1000': '0001'}, {'0110': '1000', '0111': '0101', '0000': '0011', '0001': '0000', '0011': '1010', '0010': '1101', '0101': '0110', '0100': '1111', '1111': '1110', '1110': '0100', '1100': '0010', '1101': '1011', '1010': '0111', '1011': '0001', '1001': '1100', '1000': '1001'}, {'0110': '0110', '0111': '1111', '0000': '0000', '0001': '1100', '0011': '0010', '0010': '1101', '0101': '0011', '0100': '0101', '1111': '1000', '1110': '1011', '1100': '1110', '1101': '0100', '1010': '0111', '1011': '0001', '1001': '1010', '1000': '1001'}, {'0110': '1110', '0111': '1011', '0000': '1010', '0001': '0100', '0011': '0010', '0010': '0101', '0101': '1101', '0100': '0001', '1111': '1000', '1110': '0111', '1100': '1100', '1101': '0110', '1010': '1001', '1011': '1111', '1001': '0011', '1000': '0000'}, {'0110': '1011', '0111': '0101', '0000': '0001', '0001': '1101', '0011': '1110', '0010': '0010', '0101': '1010', '0100': '0100', '1111': '0000', '1110': '0111', '1100': '1001', '1101': '1100', '1010': '1000', '1011': '0011', '1001': '0110', '1000': '1111'}, {'0110': '0110', '0111': '0001', '0000': '1111', '0001': '0010', '0011': '0100', '0010': '1010', '0101': '0111', '0100': '1000', '1111': '1101', '1110': '0000', '1100': '1011', '1101': '1110', '1010': '1100', '1011': '0011', '1001': '1001', '1000': '0101'}, {'0110': '1111', '0111': '0010', '0000': '1100', '0001': '1010', '0011': '0101', '0010': '1001', '0101': '1101', '0100': '0110', '1111': '0100', '1110': '0001', '1100': '1011', '1101': '1110', '1010': '0111', '1011': '1000', '1001': '0011', '1000': '0000'}]

PHI = 0x9e3779b9
ROUNDS = 32

@register_primitive()
class Serpent(BlockCipher):
    """
    Structure: Substitution–permutation network
    Key size: 128, 192, 256 bits
    Block size: 128 bits
    """

    CONSTRUCTION_TYPES = [ConstructionType.SUBSTITUTION_PERMUTATION_NETWORK]

    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Bytes-like object to key the cipher.
        """
        Primitive.__init__(self)

        self.key = Bytes(key, byteorder='big')
        self._stretch_key()
        self.key = Bytes(self.key.int(), 'little').zfill(32)

        self.K, self.K_hat = self.make_subkeys()


    def __reprdir__(self):
        return ['key', 'K', 'K_hat']

    def _stretch_key(self):
        if len(self.key) != 32:
            self.key = Bitstring('1', 'big', auto_fill=False).zfill((32 - len(self.key)) * 8).bytes() + self.key


    def make_subkeys(self):
        w = {}

        for i, chunk in enumerate(self.key.chunk(4)[::-1]):
            w[i - 8] = chunk[::-1].int()

        for i in range(132):
            w[i] = (left_rotate(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ i, 11))

        w = {i: Bitstring(val, 'little', auto_fill=False)[::-1] for i, val in w.items()}

        k = {}
        for i in range(ROUNDS + 1):
            sbox = (ROUNDS + 3 - i) % ROUNDS
            for h in range(4):
                k[h + 4 * i] = Bitstring("", 'little', auto_fill=False)

            for j in range(ROUNDS):
                s_in = ''.join([str(Bitstring(w[h+4*i], 'little', auto_fill=False).zfill(32)[j]) for h in range(4)])
                s_out = Bitstring(SBOX[sbox % len(SBOX)][s_in], 'little', auto_fill=False)

                for h in range(4):
                    k[h + 4 * i] += s_out[h]

        K = []
        for i in range(ROUNDS + 1):
            K.append(k[4*i] + k[4*i+1] + k[4*i+2] + k[4*i+3])


        K_hat = []
        for i in range(ROUNDS + 1):
            K_hat.append(self.IP(K[i]))

        return K, K_hat


    def _apply_sbox(self, box_num, bitstring, sbox_table):
        result = ""
        for i in range(32):
            result += sbox_table[box_num % len(sbox_table)][bitstring[i*4:(i+1)*4]]
        return result


    def S_hat(self, box_num, bitstring):
        return self._apply_sbox(box_num, bitstring, SBOX)


    def S_hat_inv(self, box_num, bitstring):
        return self._apply_sbox(box_num, bitstring, SBOX_INV)


    def _apply_LT(self, bitstring, lt_table):
        result = ""
        for i in range(len(lt_table)):
            outbit = Bitstring('0', 'little', auto_fill=False)

            for j in lt_table[i]:
                outbit ^= bitstring[j]

            result += outbit

        return result



    def LT(self, bitstring):
        return self._apply_LT(bitstring, LT_TABLE)


    def LT_inv(self, bitstring):
        return self._apply_LT(bitstring, LT_TABLE_INV)


    def R(self, i, B_hat_i):
        S_hat_i = self.S_hat(i, B_hat_i ^ self.K_hat[i])
        if i <= (ROUNDS - 2):
            B_hat_i_1 = self.LT(S_hat_i)
        else:
            B_hat_i_1 = S_hat_i ^ self.K_hat[ROUNDS]

        return B_hat_i_1



    def R_inv(self, i, B_hat_i_1):
        if i <= (ROUNDS - 2):
            S_hat_i = self.LT_inv(B_hat_i_1)
        else:
            S_hat_i = B_hat_i_1 ^ self.K_hat[ROUNDS]

        B_hat_i = self.S_hat_inv(i, S_hat_i) ^ self.K_hat[i]
        return B_hat_i


    def _apply_permutation(self, perm_table, bitstring):
        result = ""
        for i in range(len(perm_table)):
            result += bitstring[perm_table[i]]

        return result


    def IP(self, bitstring):
        return self._apply_permutation(IP_TABLE, bitstring)


    def FP(self, bitstring):
        return self._apply_permutation(FP_TABLE, bitstring)



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext_formatted = Bitstring.wrap(plaintext, 'little', auto_fill=False)[::-1].zfill(128)
        B_hat = self.IP(plaintext_formatted)

        for i in range(ROUNDS):
            B_hat = self.R(i, B_hat)

        # Attempt to preserve the user's sanity
        little_endian_ct = self.FP(B_hat)[::-1]
        return Bytes(little_endian_ct.int(), 'big').zfill(16)



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext_formatted = Bitstring.wrap(ciphertext, 'little', auto_fill=False)[::-1].zfill(128)
        B_hat = self.IP(ciphertext_formatted)

        for i in range(ROUNDS - 1, -1, -1):
            B_hat = self.R_inv(i, B_hat)

        # Attempt to preserve the user's sanity
        little_endian_pt = Bitstring(self.FP(B_hat)[::-1], 'little', auto_fill=False)
        return Bytes(little_endian_pt.int(), 'big').zfill(16)
