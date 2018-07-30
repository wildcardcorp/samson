#!/usr/bin/python3
import codecs
from samson.utilities import xor_buffs, stretch_key
import itertools
import struct
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

def count_bytes(in_bytes):
    byte_ctr = {curr_byte: 0 for curr_byte in in_bytes}
    for curr_byte in in_bytes:
        byte_ctr[curr_byte] += 1

    return byte_ctr

def is_readable_ascii(plaintext):
    is_readable = True
    for char in plaintext:
        is_readable = is_readable and (char in ascii_range)
    return is_readable


def attempt_key(key, in_bytes):
    plaintext = xor_buffs(in_bytes, stretch_key(key, len(in_bytes)))

    # is_readable = True
    # for char in plaintext:
    #     is_readable = is_readable and (char in ascii_range)

    return plaintext, is_readable_ascii(plaintext)


def frequency_analysis(in_bytes):
    try:
        as_str = in_bytes.decode()
    except UnicodeDecodeError as e:
        return 0

    words = as_str.split(' ')
    word_freq = sum([1 for w in words if len(w) > 2 and len(w) < 8])
    alphabet_ratio = sum([1 for char in as_str.lower() if char in string.ascii_lowercase]) / len(as_str)
    return (num_common_chars(as_str) * (word_freq + 0.1)) * alphabet_ratio


def num_ascii(in_bytes):
    return sum([1 for char in in_bytes if char in ascii_range]) / len(in_bytes)


def num_alpha(in_bytes):
    return sum([1 for char in in_bytes if char in list(range(65, 122))]) / len(in_bytes)


def num_common_chars(in_bytes):
    return sum([len_chars - common_chars.index(chr(char).upper()) for char in in_bytes if chr(char).lower() in common_chars]) / len(in_bytes)


def num_first_letters(in_bytes):
    try:
        as_str = in_bytes.decode()
    except UnicodeDecodeError as e:
        return 0

    return sum([first_letter_frequencies[char] for char in as_str.lower() if char in first_letter_frequencies]) / len(in_bytes)


def num_capital_letters(in_bytes):
    return sum([1 for char in in_bytes if char in range(65, 90)]) / len(in_bytes)


def build_candidates(in_bytes, key_length):
    all_keys = itertools.product(range(2), repeat=key_length)
    candidates = []

    for key in all_keys:
        bin_key = b''
        for i in range(max(key_length // 8, 1)):
            bin_key += struct.pack('B', int(''.join([str(curr_int) for curr_int in key[i * 8: (i + 1) * 8]]), 2))

        plaintext, is_readable = attempt_key(bin_key, in_bytes)

        candidates.append((bin_key, plaintext))
        # if is_readable:
        #     candidates.append((bin_key, plaintext))


    return sorted(candidates, key=lambda x: frequency_analysis(x[1]), reverse=True)


if __name__ == '__main__':
    hexinput1 = codecs.decode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex_codec')
    print(build_candidates(hexinput1, 8)[0])
