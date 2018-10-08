from samson.analyzers.english_analyzer import EnglishAnalyzer
from samson.utilities.manipulation import xor_buffs
import codecs

class XORDictionaryAttack(object):
    def __init__(self, analyzer, wordlist):
        self.analyzer = analyzer
        self.wordlist = wordlist
        
    
    def execute(self, ciphertexts, word_ranges=[2,3,4]):
        two_time = xor_buffs(*ciphertexts)

        cipher_len = len(two_time)
        trimmed_list = [word for word in self.wordlist if len(word) <= cipher_len]
        prepend_list = ['']

        last_num_processed = 0
        results = []

        for j in word_ranges:
            for i in range(j - last_num_processed):
                word_scores = []
                for prepend in prepend_list:
                    for word in trimmed_list:
                        mod_word = (prepend + ' ' + word).strip()
                        xor_result = xor_buffs((bytes(mod_word, 'utf-8') + b'\x00' * cipher_len)[:cipher_len], two_time)[:len(two_time)]
                        analysis = self.analyzer.analyze(xor_result)
                        word_scores.append((mod_word, analysis / (len(word) ** 2)))

                prepend_list = [word for word, _ in sorted(word_scores, key=lambda score: score[1], reverse=True)[:10 ** (i + 1 + last_num_processed)]]
            last_num_processed = j

            results.append(sorted(prepend_list, key=lambda word: self.analyzer.analyze(xor_buffs((bytes(word, 'utf-8') + b'\x00' * cipher_len)[:cipher_len], two_time)), reverse=True)[:10])
            
        return results