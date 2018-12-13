from samson.constructions.feistel_network import FeistelNetwork
from samson.utilities.bytes import Bytes
from samson.utilities.encoding import bytes_to_bitstring
from samson.utilities.manipulation import left_rotate

# https://en.wikipedia.org/wiki/Data_Encryption_Standard

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]


S1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

S2 = [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
]

S3 = [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
]

S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
]

S5 = [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
]

S6 = [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
]

S7 = [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
]

S8 = [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
]


sboxes = [S1, S2, S3, S4, S5, S6, S7, S8]


pbox = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

PC_1_left = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
]

PC_1_right = [
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

PC_2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

rotation_round_map = [*[1] * 2, *[2] * 6, 1, *[2] * 6, 1]


def key_schedule(key):
    key_bits = bytes_to_bitstring(key)

    left_key = ''.join([key_bits[PC_1_left[i] - 1] for i in range(28)])
    right_key = ''.join([key_bits[PC_1_right[i] - 1] for i in range(28)])

    for i in range(16):
        # Rotate
        rotation = rotation_round_map[i]

        left_key = bin(left_rotate(int(left_key, 2), rotation, bits=28))[2:].zfill(28)
        right_key = bin(left_rotate(int(right_key, 2), rotation, bits=28))[2:].zfill(28)

        # Permutate
        combined_keys = left_key + right_key
        sub_key = int.to_bytes(int(''.join([combined_keys[PC_2[j] - 1] for j in range(48)]), 2), 7, 'big')

        yield sub_key



# http://styere.xyz/JS-DES.html
def round_func(R_i, k_i):
    # Need to pad with the first since the Feistel function requires 'adjacent' bits for the expanded blocks
    R_i_bits = bytes_to_bitstring(R_i)
    R_i_bits = R_i_bits[-1] + R_i_bits + R_i_bits[0]

    # Expansion
    expanded_pt = ''.join([R_i_bits[i*4:(i+1)*4 + 2] for i in range(8)])

    # Key mixing
    K_i_bits = bytes_to_bitstring(k_i)[8:]
    mixed = [int(bitA) ^ int(bitB) for bitA, bitB in zip(expanded_pt, K_i_bits)]


    # Substitution
    blocks = [mixed[i*6:(i+1)*6] for i in range(8)]
    substitutions = []
    for i, block in enumerate(blocks):
        row = (block[0]<<1) + block[-1]
        column = sum([bit<<j for j,bit in enumerate(block[1:5][::-1])])

        substitutions.append(sboxes[i][row][column])


    # Permutation
    full_sub_string = ''.join([bin(sub)[2:].zfill(4) for sub in substitutions])
    permutations = ''.join([full_sub_string[pbox[i] - 1] for i in range(32)])
    return int.to_bytes(int(permutations, 2), 4, 'big')


class DES(FeistelNetwork):
    """
    Structure: Feistel Network
    Key size: 64 (56, actually)
    Block size: 64
    """

    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Bytes-like object to key the cipher.
        """
        super().__init__(round_func, key_schedule)
        self.key = key
        self.block_size = 8


    def __repr__(self):
        return f"<DES: key={self.key}>"

    def __str__(self):
        return self.__repr__()


    def process_plaintext(self, plaintext):
        plaintext_bitstring = bytes_to_bitstring(plaintext)
        return int.to_bytes(int(''.join([plaintext_bitstring[IP[i] - 1] for i in range(64)]), 2), 8, 'big')


    def process_ciphertext(self, ciphertext):
        ciphertext_bitstring = bytes_to_bitstring(ciphertext)
        return int.to_bytes(int(''.join([ciphertext_bitstring[FP[i] - 1] for i in range(64)]), 2), 8, 'big')


    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        permuted_plaintext = self.process_plaintext(plaintext)
        result = FeistelNetwork.encrypt(self, self.key, permuted_plaintext)
        return Bytes(self.process_ciphertext(result))


    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        permuted_ciphertext = self.process_plaintext(ciphertext)
        result = FeistelNetwork.decrypt(self, self.key, permuted_ciphertext)
        return Bytes(self.process_ciphertext(result))
