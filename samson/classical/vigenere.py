from samson.utilities.analysis import chisquare, count_bytes
from samson.utilities.bytes import Bytes
from samson.analyzers.english_analyzer import EnglishAnalyzer
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


    
    def __repr__(self):
        return "<Vigenere: key={}, alphabet={}>".format(self.key, self.alphabet)

    def __str__(self):
        return self.__repr__()

    def encrypt(self, plaintext):
        result = []

        for i, char in enumerate(plaintext):
            k_i = bytes([self.key[i % len(self.key)]])
            c_i_idx = (self.alphabet.index(bytes([char])) + self.alphabet.index(k_i)) % len(self.alphabet)
            result.append(self.alphabet[c_i_idx])

        return Bytes(bytes(result))

    
    def decrypt(self, ciphertext):
        result = []

        for i, char in enumerate(ciphertext):
            k_i = bytes([self.key[i % len(self.key)]])
            p_i_idx = (self.alphabet.index(bytes([char])) - self.alphabet.index(k_i)) % len(self.alphabet)
            result.append(self.alphabet[p_i_idx])

        return Bytes(bytes(result))


    @staticmethod
    def break_vigenere(ciphertext, alphabet=bytes(string.ascii_lowercase, 'utf-8'), expected_distribution=letter_distribution, min_key_length=1, max_key_length=20):
        ciphertext = Bytes.wrap(ciphertext)
        cipher_scores = []
        cipher_len = len(ciphertext)

        analyzer = EnglishAnalyzer()

        for i in range(min_key_length, max_key_length):
            transposed = ciphertext.transpose(i)
            total_key_score = 1
            top_chunk_scores = []

            for chunk in transposed.chunk(cipher_len // i):
                curr_chunk_scores = []

                for char in alphabet:
                    tmp_vig = Vigenere(bytes([char]))
                    new_chunk = tmp_vig.decrypt(chunk)

                    chunk_score = chisquare(count_bytes(new_chunk), expected_distribution)
                    #chunk_score = analyzer.analyze(new_chunk)
                    curr_chunk_scores.append((char, chunk_score))


                top_chunk_scores.append(sorted(curr_chunk_scores, key=lambda chunk_score: chunk_score[1], reverse=False)[0])
                #top_chunk_scores.append(sorted(curr_chunk_scores, key=lambda chunk_score: chunk_score[1], reverse=True)[0])

            for chunk_score in top_chunk_scores:
                total_key_score += chunk_score[1]
                
            cipher_scores.append((total_key_score, top_chunk_scores))

        # top_key_score = sorted(cipher_scores, key=lambda kv: kv[0])[0]
        analyzer_scores = []
        for _total_score, top_chunk_scores in cipher_scores:
            vig = Vigenere(bytes([char for char,score in top_chunk_scores]), alphabet=alphabet)
            #print(vig.decrypt(ciphertext))
            analyzer_scores.append((analyzer.analyze(vig.decrypt(ciphertext)) / len(vig.key), vig))

        #top_key_score = sorted(cipher_scores, key=lambda kv: kv[0], reverse=True)[0]
        top_analyzed_score = sorted(analyzer_scores, key=lambda kv: kv[0], reverse=True)[0]
        return top_analyzed_score[1]
        #return Vigenere(bytes([char for char,score in top_key_score[1]]), alphabet=alphabet)
        # return Vigenere(bytes([char for char,score in top_key_score[1]]), alphabet=alphabet)