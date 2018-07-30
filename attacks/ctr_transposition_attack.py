from samson.utilities import *

class CTRTranspositionAttack(object):
    def __init__(self, analyzer, decrypter, block_size):
        self.decrypter = decrypter
        self.analyzer = analyzer
        self.block_size = block_size


    def execute(self, ciphertexts):
        min_last_block = min([len(ciphertext) // self.block_size for ciphertext in ciphertexts])

        same_size_ciphers = [ciphertext[:min_last_block * self.block_size] for ciphertext in ciphertexts]
        transposed_ciphers = [bytearray(transposed) for transposed in zip(*same_size_ciphers)]
        assert [bytearray(transposed) for transposed in zip(*transposed_ciphers)] == same_size_ciphers


        transposed_plaintexts = []
        for i, cipher in enumerate(transposed_ciphers):
            all_chars = {}
            for char in range(256):
                plaintext = self.decrypter(struct.pack('B', char), cipher)

                all_chars[char] = (self.analyzer.analyze(plaintext), plaintext)

                # if i == 0:
                #     all_chars[char] = (num_first_letters(plaintext) * num_capital_letters(plaintext), plaintext)
                # else:
                #     all_chars[char] = (num_alpha(plaintext) * num_common_chars(plaintext), plaintext)

            transposed_plaintexts.append(sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1])

        return [bytearray(transposed) for transposed in zip(*transposed_plaintexts)]
        # print([bytearray(transposed) for transposed in zip(*transposed_plaintexts)])

