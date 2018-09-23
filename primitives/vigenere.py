from samson.utilities.analysis import chisquare, count_bytes
import string


letter_freq = {
    b'e': 0.1249,
    b't': 0.0928,
    b'a': 0.0804,
    b'o': 0.0764,
    b'i': 0.0757,
    b'n': 0.0723,
    b's': 0.0651,
    b'r': 0.0628,
    b'h': 0.0505,
    b'l': 0.0407,
    b'd': 0.0382,
    b'c': 0.0334,
    b'u': 0.0273,
    b'm': 0.0251,
    b'f': 0.0240,
    b'p': 0.0214,
    b'g': 0.0187,
    b'w': 0.0168,
    b'y': 0.0166,
    b'b': 0.0148,
    b'v': 0.0105,
    b'k': 0.0054,
    b'x': 0.0023,
    b'j': 0.0016,
    b'q': 0.0012,
    b'z': 0.0009
}


letter_distribution = {}
for key, val in letter_freq.items():
    letter_distribution[ord(key)] = val



class Vigenere(object):
    def __init__(self, key, alphabet=bytes(string.ascii_lowercase, 'utf-8')):
        self.key = key
        self.alphabet = alphabet
    

    def encrypt(self, plaintext):
        result = []

        for i, char in enumerate(plaintext):
            k_i = bytes([self.key[i % len(self.key)]])
            c_i_idx = (self.alphabet.index(bytes([char])) + self.alphabet.index(k_i)) % len(self.alphabet)
            result.append(self.alphabet[c_i_idx])

        return bytes(result)

    
    def decrypt(self, ciphertext):
        result = []

        for i, char in enumerate(ciphertext):
            k_i = bytes([self.key[i % len(self.key)]])
            p_i_idx = (self.alphabet.index(bytes([char])) - self.alphabet.index(k_i)) % len(self.alphabet)
            result.append(self.alphabet[p_i_idx])

        return bytes(result)


    @staticmethod
    def break_vigenere(ciphertext):
        cipher_scores = []
        cipher_len = len(ciphertext)

        for i in range(1, 5):
            transposed = ciphertext.transpose(i)
            total_key_score = 1
            top_chunk_scores = []

            for chunk in transposed.chunk(cipher_len // i):
                curr_chunk_scores = []

                for j in range(26):
                    new_chunk = []

                    for c in chunk:
                        new_c = (c - 97 + j) % 26 + 97
                        new_chunk.append(new_c)

                    chunk_score = chisquare(count_bytes(bytes(new_chunk)), letter_distribution)
                    curr_chunk_scores.append((j, chunk_score))

                top_chunk_scores.append(sorted(curr_chunk_scores, key=lambda chunk_score: chunk_score[1], reverse=False)[:2])

            for chunk_score in top_chunk_scores:
                total_key_score *= chunk_score[0][1]
                
            cipher_scores.append((total_key_score, top_chunk_scores))

        return cipher_scores