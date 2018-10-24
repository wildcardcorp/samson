
from samson.utilities.math import mod_inv, lll, generate_superincreasing_seq, find_coprime
from samson.utilities.bytes import Bytes
import numpy as np
from sympy.matrices import Matrix, eye


class MerkleHellmanKnapsack(object):
    def __init__(self, priv=None, q=None, r=None, max_diff=2**20, pub_len=8):
        super_seq = generate_superincreasing_seq(pub_len + 1, max_diff, starting=Bytes.random(max(1, pub_len // 8)).int())
        self.priv = priv or super_seq[:pub_len]
        self.q = q or super_seq[-1]
        self.r = r or find_coprime(self.q, range(self.q // 4, self.q))

        self.pub = [(w * self.r) % self.q for w in self.priv]


    def __repr__(self):
        return f"<MerkleHellmanKnapsack: priv={self.priv}, pub={self.pub}, q={self.q}, r={self.r}>"
    

    def __str__(self):
        return self.__repr__()


    def encrypt(self, message):
        bin_str = ''
        for byte in message:
            bin_str += bin(byte)[2:].zfill(8)

        all_sums = []
        
        for i in range(len(bin_str) // len(self.pub)):
            byte_str = bin_str[i * len(self.pub):(i + 1) * len(self.pub)]
            all_sums.append(sum([int(byte_str[j]) * self.pub[j] for j in range(len(self.pub))]))

        return all_sums


    def decrypt(self, sums):
        r_inv = mod_inv(self.r, self.q)
        inv_sums = [(byte_sum * r_inv) % self.q for byte_sum in sums]
        plaintext = Bytes(b'')

        for inv_sum in inv_sums:
            curr = inv_sum
            bin_string = ''

            for i in range(len(self.pub) - 1, -1, -1):
                if self.priv[i] <= curr:
                    curr -= self.priv[i]
                    bin_string += '1'
                else:
                    bin_string += '0'

            plaintext += int.to_bytes(int(bin_string[::-1], 2), len(self.pub) // 8, 'big')

        return plaintext


    @staticmethod
    def recover_plaintext(ciphertext, pub):
        ident = eye(len(pub))
        pub_matrix = ident.col_join(Matrix([pub]))
        problem_matrix = pub_matrix.row_join(Matrix([[0] * len(pub) + [-ciphertext]]).T).T

        matrices = [problem_matrix.row(row) for row in range(problem_matrix.rows)]
        print(matrices)
        solution_matrix = lll(matrices, 0.99)

        for row in range(solution_matrix.rows):
            row_mat = solution_matrix.row(row)
            new_row = [item for item in row_mat if item >= 0 and item <= 1]

            if len(new_row) == len(row_mat):
                return int(''.join([str(val) for val in row_mat[:-1]]), 2)
        return solution_matrix