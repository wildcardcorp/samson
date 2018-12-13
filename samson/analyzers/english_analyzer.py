from samson.analyzers.analyzer import Analyzer
from samson.utilities.analysis import count_items, chisquare
from samson.auxiliary.tokenizer import Tokenizer
from samson.auxiliary.token_list_handler import TokenListHandler
from samson.auxiliary.cracklib_wordlist import CRACKLIB_WORDLIST
import string
import re

ascii_range = [10, 13] + list(range(20, 127))

wordlist = {word.strip(): 0 for word in CRACKLIB_WORDLIST}

first_letter_frequencies = {
    't': .15978,
    'a': .11682,
    'o': .07631,
    'i': .07294,
    's': .06686,
    'w': .05497,
    'c': .05238,
    'b': .04434,
    'p': .04319,
    'h': .04200,
    'f': .04027,
    'm': .03826,
    'd': .03174,
    'r': .02826,
    'e': .02799,
    'l': .02415,
    'n': .02284,
    'g': .01642,
    'u': .01183,
    'v': .00824,
    'y': .00763,
    'j': .00511,
    'k': .00456,
    'q': .00222,
    'x': .00045,
    'z': .00045
}

letter_freq = {
    'e': 0.1249,
    't': 0.0928,
    'a': 0.0804,
    'o': 0.0764,
    'i': 0.0757,
    'n': 0.0723,
    's': 0.0651,
    'r': 0.0628,
    'h': 0.0505,
    'l': 0.0407,
    'd': 0.0382,
    'c': 0.0334,
    'u': 0.0273,
    'm': 0.0251,
    'f': 0.0240,
    'p': 0.0214,
    'g': 0.0187,
    'w': 0.0168,
    'y': 0.0166,
    'b': 0.0148,
    'v': 0.0105,
    'k': 0.0054,
    'x': 0.0023,
    'j': 0.0016,
    'q': 0.0012,
    'z': 0.0009
}

most_common_words = {
    'the': .0714,
    'of': .0416,
    'and': .0304,
    'to': .0260,
    'in': .0227,
    'a': .0206,
    'is': .0113,
    'that': .0108,
    'for': .0088,
    'it': .0077,
    'as': .0077,
    'was': .0074,
    'with': .0070,
    'be': .0065,
    'by': .0063,
    'on': .0062,
    'not': .0061,
    'he': .0055,
    'i': .0052,
    'this': .0051,
    'are': .0050,
    'or': .0049,
    'his': .0049,
    'from': .0047,
    'at': .0046,
    'which': .0042,
    'but': .0038,
    'have': .0037,
    'an': .0037,
    'had': .0035,
    'they': .0033,
    'you': .0031,
    'were': .0031,
    'their': .0029,
    'one': .0029,
    'all': .0028,
    'we': .0028,
    'can': .0022,
    'her': .0022,
    'has': .0022,
    'there': .0022,
    'been': .0022,
    'if': .0021,
    'more': .0021,
    'when': .0020,
    'will': .0020,
    'would': .0020,
    'who': .0020,
    'so': .0019,
    'no': .0019
}

most_common_bigrams = {
    'TH': .0356,
    'HE': .0307,
    'IN': .0243,
    'ER': .0205,
    'AN': .0199,
    'RE': .0185,
    'ON': .0176,
    'AT': .0149,
    'EN': .0145,
    'ND': .0135,
    'TI': .0134,
    'ES': .0134,
    'OR': .0128,
    'TE': .0120,
    'OF': .0117,
    'ED': .0117,
    'IS': .0113,
    'IT': .0112,
    'AL': .0109,
    'AR': .0107,
    'ST': .0105,
    'TO': .0104,
    'NT': .0104,
    'NG': .0095,
    'SE': .0093,
    'HA': .0093,
    'AS': .0087,
    'OU': .0087,
    'IO': .0083,
    'LE': .0083,
    'VE': .0083,
    'CO': .0079,
    'ME': .0079,
    'DE': .0076,
    'HI': .0076,
    'RI': .0073,
    'RO': .0073,
    'IC': .0070,
    'NE': .0069,
    'EA': .0069,
    'RA': .0069,
    'CE': .0065,
    'LI': .0062,
    'CH': .0060,
    'LL': .0058,
    'BE': .0058,
    'MA': .0057,
    'SI': .0055,
    'OM': .0055,
    'UR': .0054
}



def _num_common_words(string):
    return sum([val * string.count(word) for word, val in most_common_words.items()]) / len(string)


def _num_common_letters(string):
    return sum([val * string.count(letter) for letter, val in letter_freq.items()]) / len(string)


def _num_common_first_letters(string):
    words = string.split(' ')
    return sum([first_letter_frequencies[word[0]] for word in words if len(word) > 0 and word[0] in first_letter_frequencies]) / len(words)


def _num_bigrams(string):
    return sum([val * string.count(bigram.lower()) for bigram, val in most_common_bigrams.items()]) / len(string)

TOKENIZER = Tokenizer([word for word, _ in wordlist.items() if len(word) > 2], TokenListHandler)

class EnglishAnalyzer(Analyzer):
    """
    Analyzer for English text.
    """

    def __init__(self):
        pass


    def analyze(self, in_bytes: bytes) -> float:
        """
        Takes in a bytes-like object and returns a relative score.

        Parameters:
            in_bytes (bytes): The bytes-like object to be "scored".
        
        Returns:
            float: The relative score of the object.
        """
        try:
            as_str = in_bytes.decode()
        except UnicodeDecodeError as _:
            return 0

        str_lower = as_str.lower()
        words = [word for word in re.split('[?.,! ]', str_lower) if word != '']
        word_freq = sum([1 for w in words if len(w) > 2 and len(w) < 8])


        alphabet_ratio = sum([1 for char in str_lower if char in string.ascii_lowercase]) / len(as_str)
        ascii_ratio = sum([1 for char in str_lower if ord(char) in ascii_range]) / len(as_str)

        common_words = _num_common_words(str_lower)
        first_letter_freq = _num_common_first_letters(str_lower)
        bigrams = _num_bigrams(str_lower)

        found_words = sum([len(word) ** 2 for word in TOKENIZER.tokenize([str_lower])])

        expected_english_distribution = {}
        for letter, freq in letter_freq.items():
            expected_english_distribution[bytes(letter, 'utf-8')] = freq * len(in_bytes)


        # We divide it by the `length*2` to normalize it since I empirically found that the chisquared of
        # a uniform distribution of `length` bytes tends towards it.
        chisquared_analysis = 1 / (chisquare(count_items(in_bytes), expected_english_distribution) / (len(in_bytes) * 2))

        return ((_num_common_letters(as_str.lower()) + 1) * (word_freq * 2 + 1)) * (((alphabet_ratio + 1) ** 5 - 1) * 60) * ((ascii_ratio + 1) ** 2 - 1) * (common_words + 1) * (first_letter_freq + 1) * (bigrams * 25 + 1) * (found_words + 1) * chisquared_analysis



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
        try:
            as_str = in_bytes.decode()
        except UnicodeDecodeError as _:
            return {
                'word_freq': 0.0,
                'alphabet_ratio': 0.0,
                'ascii_ratio': 0.0,
                'common_letters': 0.0,
                'common_words': 0.0,
                'first_letter_freq': 0.0,
                'bigrams': 0.0
            }


        words = as_str.split(' ')
        word_freq = sum([1 for w in words if len(w) > 2 and len(w) < 8]) / len(as_str)


        alphabet_ratio = sum([1 for char in as_str.lower() if char in string.ascii_lowercase]) / len(as_str)
        ascii_ratio = sum([1 for char in as_str.lower() if ord(char) in ascii_range]) / len(as_str)

        common_words = _num_common_words(as_str.lower())
        common_letters = _num_common_letters(as_str.lower())
        first_letter_freq = _num_common_first_letters(as_str.lower())
        bigrams = _num_bigrams(as_str.lower())

        return_dict = {
            'word_freq': word_freq,
            'alphabet_ratio': alphabet_ratio,
            'ascii_ratio': ascii_ratio,
            'common_letters': common_letters,
            'common_words': common_words,
            'first_letter_freq': first_letter_freq,
            'bigrams': bigrams
        }

        if in_ciphers != None:
            return_dict['is_correct'] = int(in_bytes in in_ciphers)

        return return_dict
