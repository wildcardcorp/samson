#!/usr/bin/python3
from samson.aes_ctr import AES_CTR
from samson.utilities import gen_rand_key
from samson.utilities import transpose
from samson.xor import find_key_size
from samson.utilities import get_blocks
from samson.utilities import xor_buffs, stretch_key
from samson.ch1_3 import build_candidates, frequency_analysis, num_ascii, num_alpha, num_common_chars, num_first_letters, num_capital_letters
from samson.attacks.ctr_transposition_attack import CTRTranspositionAttack
from samson.analyzers.english_analyzer import EnglishAnalyzer
import base64
import struct

key = gen_rand_key()

def encrypt(secret):
    aes = AES_CTR(key, struct.pack('Q', 0))
    return aes.encrypt(secret)


def attempt_key(key, in_bytes):
    plaintext = xor_buffs(in_bytes, stretch_key(key, len(in_bytes)))
    #, is_readable_ascii(plaintext)
    return plaintext


if __name__ == '__main__':
    with open('tests/test_ctr_transposition.txt') as f:
        secrets = [base64.b64decode(line.strip().encode()) for line in f.readlines()]

    block_size = 16

    ciphertexts = [encrypt(secret) for secret in secrets]

    attack = CTRTranspositionAttack(EnglishAnalyzer(attempt_key), attempt_key, 16)
    recovered_plaintexts = attack.execute(ciphertexts)

    print(recovered_plaintexts)

    # min_last_block = min([len(ciphertext) // block_size for ciphertext in ciphertexts])

    # same_size_ciphers = [ciphertext[:min_last_block * block_size] for ciphertext in ciphertexts]
    # transposed_ciphers = [bytearray(transposed) for transposed in zip(*same_size_ciphers)]
    # assert [bytearray(transposed) for transposed in zip(*transposed_ciphers)] == same_size_ciphers


    # transposed_plaintexts = []
    # for i, cipher in enumerate(transposed_ciphers):
    #     all_chars = {}
    #     for char in range(256):
    #         plaintext, is_readable = attempt_key(struct.pack('B', char), cipher)

    #         if i == 0:
    #             all_chars[char] = (num_first_letters(plaintext) * num_capital_letters(plaintext), plaintext)
    #         else:
    #             all_chars[char] = (num_alpha(plaintext) * num_common_chars(plaintext), plaintext)

    #     transposed_plaintexts.append(sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1])

    # print([bytearray(transposed) for transposed in zip(*transposed_plaintexts)])
