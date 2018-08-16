from samson.utilities import *
import pandas as pd
from copy import deepcopy
import pickle

with open('/home/donald/Git/samson/attacks/english_stat_model.bin', 'rb') as f:
    statistical_model = pickle.loads(f.read())

class CTRTranspositionAttack(object):
    def __init__(self, analyzer, decrypter, block_size):
        self.decrypter = decrypter
        self.analyzer = analyzer
        self.block_size = block_size


    def execute(self, ciphertexts):
        #min_last_block = min([len(ciphertext) // self.block_size for ciphertext in ciphertexts])
        min_size = min([len(ciphertext) for ciphertext in ciphertexts])

        #same_size_ciphers = [ciphertext[:min_last_block * self.block_size] for ciphertext in ciphertexts]
        same_size_ciphers = [ciphertext[:min_size] for ciphertext in ciphertexts]
        transposed_ciphers = [bytearray(transposed) for transposed in zip(*same_size_ciphers)]
        assert [bytearray(transposed) for transposed in zip(*transposed_ciphers)] == same_size_ciphers


        # Transposition analysis first (transposition)
        transposed_plaintexts = []
        for cipher in transposed_ciphers:
            all_chars = {}
            for char in range(256):
                plaintext = self.decrypter(struct.pack('B', char), cipher)

                all_chars[char] = (self.analyzer.analyze(plaintext), plaintext)

            transposed_plaintexts.append(sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1])


        first_pass_plaintexts = [bytearray(transposed) for transposed in zip(*transposed_plaintexts)]


        # Clean up with a character-by-character, higher-context analysis (retransposed)
        retransposed_plaintexts = []
        differential_mask = bytearray()
        #all_char_analyses = []

        for i in range(min_size):
            all_chars = {}

            for char in range(256):
                #all_analyses = []

                frames = []
                for curr_cipher in first_pass_plaintexts:
                    cipher_copy = deepcopy(curr_cipher)
                    cipher_copy[i] = ord(self.decrypter(struct.pack('B', char), struct.pack('B', curr_cipher[i])))
                    # all_analyses.append(self.analyzer.analyze(cipher_copy))
                    preprocessed_frame = self.analyzer.preprocess(cipher_copy)
                    frames.append(preprocessed_frame)

                    #all_char_analyses.append(cipher_copy)

                dataframe = pd.DataFrame(frames)
                prediction = statistical_model.predict_proba(dataframe)
                analysis = prediction[:, 0] * prediction[:, 1]

                all_chars[char] = (sum(analysis), char)
                # all_chars[char] = (sum(all_analyses), char)

            #retransposed_plaintexts.append(sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1])
            best_char = sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1]
            differential_mask += struct.pack('B', best_char)
            
        print(differential_mask)
        retransposed_plaintexts = [xor_buffs(cipher, differential_mask) for cipher in first_pass_plaintexts]

        return retransposed_plaintexts#, all_char_analyses