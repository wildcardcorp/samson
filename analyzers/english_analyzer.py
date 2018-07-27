from analyzer import Analyzer
import string


common_chars = 'ETAOIN SHRDLU'
len_chars = len(common_chars)
ascii_range = [10, 13] + list(range(20, 127))

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

def _num_ascii(in_bytes):
    return sum([1 for char in in_bytes if char in ascii_range]) / len(in_bytes)


def _num_alpha(in_bytes):
    return sum([1 for char in in_bytes if char in list(range(65, 122))]) / len(in_bytes)


def _num_common_chars(in_bytes):
    return sum([len_chars - common_chars.index(chr(char).upper()) for char in in_bytes if chr(char).lower() in common_chars]) / len(in_bytes)


def _num_first_letters(in_bytes):
    try:
        as_str = in_bytes.decode()
    except UnicodeDecodeError as e:
        return 0

    return sum([first_letter_frequencies[char] for char in as_str.lower() if char in first_letter_frequencies]) / len(in_bytes)


def _num_capital_letters(in_bytes):
    return sum([1 for char in in_bytes if char in range(65, 90)]) / len(in_bytes)





class EnglishAnalyzer(Analyzer):
    def __init__(self, attempt_key):
        self.attempt_key = attempt_key


    def analyze(self, in_bytes):
        try:
            as_str = in_bytes.decode()
        except UnicodeDecodeError as e:
            return 0

        words = as_str.split(' ')
        word_freq = sum([1 for w in words if len(w) > 2 and len(w) < 8])
        alphabet_ratio = sum([1 for char in as_str.lower() if char in string.ascii_lowercase]) / len(as_str)
        return (_num_common_chars(in_bytes) * (word_freq + 0.1)) * alphabet_ratio

