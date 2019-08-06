from samson.analyzers.analyzer import Analyzer
from samson.utilities.analysis import chisquare
from samson.auxiliary.tokenizer import Tokenizer
from samson.auxiliary.token_list_handler import TokenListHandler
from samson.auxiliary.english_data import CRACKLIB_WORDLIST, FIRST_LETTER_FREQUENCIES, MOST_COMMON_WORDS, MOST_COMMON_BIGRAMS, CHAR_FREQ, ENGLISH_ONE_GRAMS
from collections import Counter
import string
import re

TOP_50K = [k.encode('utf-8') for k,v in ENGLISH_ONE_GRAMS.items()][:50000]

ASCII_RANGE     = {k:0 for k in [10, 13] + list(range(20, 127))}
ASCII_LOWER     = {k:0 for k in bytes(string.ascii_lowercase, 'utf-8')}
WORDLIST        = {word.decode().strip(): 0 for word in CRACKLIB_WORDLIST + TOP_50K}
DELIMITER_REGEX = re.compile(b'[?.,! ]')

MOST_COMMON_BIGRAMS = {k.lower():v for k,v in MOST_COMMON_BIGRAMS.items()}

def _num_common_first_letters(words):
    if not len(words):
        return 0

    return sum([FIRST_LETTER_FREQUENCIES[bytes([word[0]])] for word in words if len(word) > 0 and bytes([word[0]]) in FIRST_LETTER_FREQUENCIES]) / len(words)


def weighted_token_ratio(in_bytes, weighted_dict, in_bytes_len):
    count = in_bytes.count
    return sum([val * count(key) for key, val in weighted_dict]) / in_bytes_len


def key_count(in_bytes, key):
    return (key, in_bytes.count(key))


TOKENIZER = Tokenizer([word for word, _ in WORDLIST.items() if len(word) > 2], TokenListHandler, delimiter=' ')
TOKENIZE  = TOKENIZER.tokenize

class EnglishAnalyzer(Analyzer):
    """
    Analyzer for English text.
    """

    def analyze(self, in_bytes: bytes) -> float:
        """
        Takes in a bytes-like object and returns a relative score.

        Parameters:
            in_bytes (bytes): The bytes-like object to be "scored".
        
        Returns:
            float: The relative score of the object.
        """
        processed_dict = self.preprocess(in_bytes)

        word_freq         = processed_dict['word_freq']
        alphabet_ratio    = processed_dict['alphabet_ratio']
        ascii_ratio       = processed_dict['ascii_ratio']
        common_words      = processed_dict['common_words']
        first_letter_freq = processed_dict['first_letter_freq']
        found_words       = processed_dict['found_words']
        delimited_words   = processed_dict['delimited_words']
        bigram_score      = processed_dict['bigram_score']

        word_score = sum([len(word) ** (3.5 + (bytes(word, 'utf-8') in delimited_words) * 1) for word in found_words])

        return (word_freq * 2 + 1) * (((alphabet_ratio + 0.6) ** 9) * 60) * ((ascii_ratio + 0.3) ** 5) * (common_words + 1) * (first_letter_freq + 1) * (word_score + 1) * (bigram_score * 25)



    def preprocess(self, in_bytes: bytes, in_ciphers: bytes=None) -> dict:
        """
        Takes in a bytes-like object and returns the processed feature-space used in scoring.
        This is good for training statistical models.

        Parameters:
            in_bytes   (bytes): The bytes-like object to be "scored".
            in_ciphers (bytes): (Optional) If set, will check if `in_bytes` is a subset of `in_ciphers`.
                                Used for supervised machine learning.
        
        Returns:
            dictionary: Dictionary containing the processed features.
        """
        bytes_lower = in_bytes.lower()
        byte_len    = len(in_bytes)

        delimited_words = [word for word in re.split(DELIMITER_REGEX, bytes_lower) if word != b'']
        word_freq       = sum([1 for w in delimited_words if len(w) > 2 and len(w) < 8 and all([letter in ASCII_RANGE for letter in w])])

        alphabet_ratio = sum([1 for char in bytes_lower if char in ASCII_LOWER]) / byte_len
        ascii_ratio    = sum([1 for char in bytes_lower if char in ASCII_RANGE]) / byte_len

        bigram_score      = weighted_token_ratio(bytes_lower, MOST_COMMON_BIGRAMS, byte_len)
        first_letter_freq = _num_common_first_letters(delimited_words)

        found_words  = TOKENIZE([bytes_lower.decode('latin-1')])
        common_words = len([word for word in found_words if word in MOST_COMMON_WORDS])

        # We divide it by the `length*2` to normalize it since I empirically found that the chisquared of
        # a uniform distribution of `length` bytes tends towards it.
        monogram_chisquared = chisquare(Counter(in_bytes), CHAR_FREQ, byte_len) / (byte_len * 2)

        return_dict = {
            'word_freq': word_freq,
            'alphabet_ratio': alphabet_ratio,
            'ascii_ratio': ascii_ratio,
            'common_words': common_words,
            'first_letter_freq': first_letter_freq,
            'found_words': found_words,
            'delimited_words': delimited_words,
            'monogram_chisquared': monogram_chisquared,
            'bigram_score': bigram_score
        }

        if in_ciphers != None:
            return_dict['is_correct'] = int(in_bytes in in_ciphers)

        return return_dict
