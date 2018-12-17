from samson.utilities.manipulation import xor_buffs
from samson.analyzers.analyzer import Analyzer

import logging
log = logging.getLogger(__name__)

# TODO: Make work with more than two ciphertexts.
class XORDictionaryAttack(object):
    """
    Preforms a plaintext recovery attack.

    Attempts to retrieve the plaintext from two or more ciphertexts using a dictionary attack.
    The basic premise is if the ciphertexts are fully contained within the wordlist,
    then XORing one ciphertext with the correct word (or whatever values are in the wordlist)
    will produce the correct keystream segment. This segment is then XOR'd with the other ciphertext and
    fed through the analyzer. The word with the highest score is most likely correct.

    Conditions:
        * A stream/OTP-like cipher is used. I.E. plaintext XOR keystream
        * The user has collected more than one ciphertext using the same keystream.
    """

    def __init__(self, analyzer: Analyzer, wordlist: list):
        """
        Parameters:
            analyzer (Analyzer): Analyzer that correctly scores the underlying plaintext.
            wordlist     (list): List of strings for the dictionary attack.
        """
        self.analyzer = analyzer
        self.wordlist = wordlist


    def execute(self, ciphertexts: list, word_ranges: list=[2,3], delimiter: str=' ') -> list:
        """
        Executes the attack.
        
        Parameters:
            ciphertexts (list): List of bytes-like ciphertexts using the same keystream.
            word_ranges (list): List of numbers of words to try. E.G. [2, 3, 4] means
                                try the Cartesian product of 2, 3, and 4-tuple word combinations.
            delimiter    (str): Delimiter to use between word combinations.
        
        Returns:
            list: Top 10 possible plaintexts.
        """
        if len(ciphertexts) != 2:
            raise ValueError('`ciphertexts` MUST contain two samples.')

        two_time = xor_buffs(*ciphertexts)

        cipher_len = len(two_time)
        trimmed_list = [word for word in self.wordlist if len(word) <= cipher_len]
        prepend_list = ['']

        last_num_processed = 0
        results = []

        for j in word_ranges:
            log.debug(f"Starting word range {j}")

            for i in range(j - last_num_processed):
                word_scores = []
                for prepend in prepend_list:
                    for word in trimmed_list:
                        mod_word = (prepend + delimiter + word).strip()
                        xor_result = xor_buffs((bytes(mod_word, 'utf-8') + b'\x00' * cipher_len)[:cipher_len], two_time)[:len(two_time)]
                        analysis = self.analyzer.analyze(xor_result)
                        word_scores.append((mod_word, analysis / (len(word) ** 2)))

                prepend_list = [word for word, _ in sorted(word_scores, key=lambda score: score[1], reverse=True)[:10 ** (i + 1 + last_num_processed)]]
            last_num_processed = j

            results.append(sorted(prepend_list, key=lambda word: self.analyzer.analyze(xor_buffs((bytes(word, 'utf-8') + b'\x00' * cipher_len)[:cipher_len], two_time)), reverse=True)[:10])

        return results
