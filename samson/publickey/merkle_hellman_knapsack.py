
from samson.utilities.math import mod_inv, lll
from samson.utilities.bytes import Bytes
import numpy as np

class MerkleHellmanKnapsack(object):
    def __init__(self, priv, q, r):
        self.priv = priv
        self.q = q
        self.r = r

        self.pub = [(w * r) % q for w in self.priv]


    def encrypt(self, message):
        bin_str = ''
        for byte in message:
            bin_str += bin(byte)[2:].zfill(8)

        all_sums = []
        
        for i in range(len(bin_str) // 8):
            byte_str = bin_str[i * 8:(i + 1) * 8]
            all_sums.append(sum([int(byte_str[j]) * self.pub[j] for j in range(8)]))

        return all_sums


    def decrypt(self, sums):
        r_inv = mod_inv(self.r, self.q)
        inv_sums = [(byte_sum * r_inv) % self.q for byte_sum in sums]
        plaintext = Bytes(b'')

        for inv_sum in inv_sums:
            curr = inv_sum
            bin_string = ''

            for i in range(7, -1, -1):
                if self.priv[i] <= curr:
                    curr -= self.priv[i]
                    bin_string += '1'
                else:
                    bin_string += '0'

            plaintext += int.to_bytes(int(bin_string[::-1], 2), 1, 'big')

        return plaintext


    @staticmethod
    def recover_plaintext(ciphertext, pub):
        ident = np.identity(len(pub))
        pub_matrix = np.append(ident, [pub], axis=0)
        problem_matrix = np.append(pub_matrix, np.array([[0] * len(pub) + [-ciphertext]]).T, axis=1)

        solution_matrix = lll(problem_matrix.T, 0.99)

        for row in solution_matrix:
            new_row = row[row[:] >= 0]
            new_row = new_row[new_row[:] <= 1]

            if len(new_row) == len(row):
                return row[:-1]