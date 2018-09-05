from samson.utilities import *
from samson.primitives.xor import decrypt
import pandas as pd
from copy import deepcopy
import pickle
import os

with open(os.path.join(os.path.dirname(__file__), 'english_stat_model.bin'), 'rb') as f:
    statistical_model = pickle.loads(f.read())

class XORTranspositionAttack(object):
    def __init__(self, analyzer, block_size):
        self.analyzer = analyzer
        self.block_size = block_size


    def execute(self, ciphertexts):
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


        first_pass_plaintexts = [bytearray(transposed) for transposed in zip(*transposed_plaintexts)]


        # Clean up with a character-by-character, higher-context analysis (retransposed)
        retransposed_plaintexts = []
        differential_mask = bytearray()

        for i in range(min_size):
            all_chars = {}

            for char in range(256):


                frames = []
                for curr_cipher in first_pass_plaintexts:
                    cipher_copy = deepcopy(curr_cipher)
                    cipher_copy[i] = ord(decrypt(struct.pack('B', char), struct.pack('B', curr_cipher[i])))

                    preprocessed_frame = self.analyzer.preprocess(cipher_copy)
                    frames.append(preprocessed_frame)


                dataframe = pd.DataFrame(frames)
                prediction = statistical_model.predict_proba(dataframe)
                analysis = prediction[:, 0] * prediction[:, 1]

                all_chars[char] = (sum(analysis), char)

            best_char = sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1]
            differential_mask += struct.pack('B', best_char)
            
        print(differential_mask)
        retransposed_plaintexts = [xor_buffs(cipher, differential_mask) for cipher in first_pass_plaintexts]

        return retransposed_plaintexts