from samson.utilities import *
from samson.primitives.xor import decrypt
from copy import deepcopy
import pickle
import os

class XORTranspositionAttack(object):
    def __init__(self, analyzer):
        self.analyzer = analyzer


    def execute(self, ciphertexts, iterations=3):
        min_size = min([len(ciphertext) for ciphertext in ciphertexts])

        same_size_ciphers = [ciphertext[:min_size] for ciphertext in ciphertexts]
        transposed_ciphers = [bytearray(transposed) for transposed in zip(*same_size_ciphers)]
        assert [bytearray(transposed) for transposed in zip(*transposed_ciphers)] == same_size_ciphers


        # Transposition analysis first (transposition)
        transposed_plaintexts = []
        for cipher in transposed_ciphers:
            all_chars = {}
            for char in range(256):
                plaintext = decrypt(struct.pack('B', char), cipher)

                all_chars[char] = (self.analyzer.analyze(plaintext), plaintext)

            transposed_plaintexts.append(sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1])


        #first_pass_plaintexts = [bytearray(transposed) for transposed in zip(*transposed_plaintexts)]

        retransposed_plaintexts = [bytearray(transposed) for transposed in zip(*transposed_plaintexts)]

        # Clean up with a character-by-character, higher-context analysis (retransposed)
        for _ in range(iterations):
            differential_mask = bytearray()

            for i in range(min_size):
                all_chars = {}

                for char in range(256):
                    full_text_analyses = []

                    frames = []
                    for curr_cipher in retransposed_plaintexts:
                        cipher_copy = deepcopy(curr_cipher)
                        cipher_copy[i] = ord(decrypt(struct.pack('B', char), struct.pack('B', curr_cipher[i])))

                        preprocessed_frame = self.analyzer.preprocess(cipher_copy)
                        frames.append(preprocessed_frame)
                        full_text_analyses.append(self.analyzer.analyze(cipher_copy))

                    all_chars[char] = (sum(full_text_analyses), char)

                best_char = sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1]
                differential_mask += struct.pack('B', best_char)
                
            retransposed_plaintexts = [xor_buffs(cipher, differential_mask) for cipher in retransposed_plaintexts]

        return retransposed_plaintexts