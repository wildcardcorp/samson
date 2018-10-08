from samson.utilities.encoding import bytes_to_bitstring
from math import ceil, log, sqrt
from samson.stream_ciphers.rc4 import RC4
import operator
from copy import deepcopy
import json
import difflib
import scipy.special
import os

RC4_BIAS_MAP = [163, 0, 131, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 240, 17, 18, 0, 20, 21, 22, 0, 24, 25, 26, 0, 28, 29, 0, 31, 224, 33, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 0, 0, 0]


def longest_substring(strA, strB):
    seqMatch = difflib.SequenceMatcher(None, strA, strB)
    match = seqMatch.find_longest_match(0, len(strA), 0, len(strB))
    return strA[match.a: match.a + match.size]



def hamming_distance(bytes1, bytes2):
    assert len(bytes1) == len(bytes2)
    bitstring1 = bytes_to_bitstring(bytes1)
    bitstring2 = bytes_to_bitstring(bytes2)

    distance = 0
    for bit1, bit2 in zip(bitstring1, bitstring2):
        if bit1 != bit2: distance += 1

    return distance


def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + 1       # than s2
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]



def count_bytes(in_bytes):
    byte_ctr = {curr_byte: 0 for curr_byte in in_bytes}
    for curr_byte in in_bytes:
        byte_ctr[curr_byte] += 1

    return byte_ctr


# Takes in two dictionaries: an 'observed_dict' and an 'expected_freq_dict'.
def chisquare(observed_dict, expected_freq_dict):
    observed_len = sum([v for _k, v in observed_dict.items()])
    total = 0
    for key, freq_value in expected_freq_dict.items():
        if key in observed_dict:
            obs_val = observed_dict[key]
        else:
            obs_val = 0
        
        expected_number = observed_len * freq_value
        total += (expected_number - obs_val) ** 2 / expected_number

    
    for key, obs_value in observed_dict.items():
        if key not in expected_freq_dict:
            obs_val = obs_value
        else:
            obs_val = 0

        total += obs_val ** 2
    
    return total


def find_key_size(cipherbytes, key_range, candidate_slice_size):
    key_distances = {}
    for size in key_range:
        size_sum = 0
        num_blocks = (len(cipherbytes) // size)
        for block in range(num_blocks - 1):
            size_sum += hamming_distance(cipherbytes[block * size: (block + 1) * size], cipherbytes[(block + 1) * size: (block + 2) * size]) / size

        key_distances[size] = size_sum / num_blocks


    candidates = sorted(key_distances.items(), key=operator.itemgetter(1))[:candidate_slice_size]
    return candidates


def birthday_attack(bits, probability):
    return sqrt(2 * 2**bits * log(1/(1-float(probability))))



def expected_collisions(bits, num_inputs):
    return 2**(-bits)*scipy.special.comb(num_inputs, 2)



def generate_rc4_bias_map(ciphertexts):
    bias_map = [{} for i in range(256)]
    for c in ciphertexts:
        for i, byte in enumerate(c):
            if byte in bias_map[i]:
                bias_map[i][byte] = bias_map[i][byte] + 1
            else:
                bias_map[i][byte] = 1

    for i,_ in enumerate(bias_map):
        bias_map[i] = sorted(bias_map[i].items(), key=lambda kv: kv[1], reverse=True)

    return bias_map



def generate_random_rc4_bias_map(data=b'\x00' * 51, key_size=128, sample_size=2**20):
    ciphertexts = []
    for _ in range(sample_size):
        key = os.urandom(key_size // 8)
        cipher = RC4(key)
        ciphertexts.append(cipher.yield_state(len(data)) ^ data)


    return generate_rc4_bias_map(ciphertexts)



def incremental_rc4_bias_map_gen(filepath, start_idx=0, data=b'\x00' * 51, key_size=128, sample_size=2**30, chunk_size=2**24):
    if sample_size % chunk_size > 0:
        iteration_mod = 1
    else:
        iteration_mod = 0


    iterations = sample_size // chunk_size + iteration_mod

    for i in range(start_idx, iterations):
        if i == iterations - 1 and iteration_mod == 1:
            mod_sample_size = sample_size % chunk_size
        else:
            mod_sample_size = chunk_size
        
        bias_map = generate_random_rc4_bias_map(data, key_size, mod_sample_size)
        

        with open(filepath + ".{}".format(i), "w+") as f:
            f.write(json.dumps(bias_map))

        del bias_map



def merge_rc4_bias_map_files(base_path, num):
    bias_maps = []
    for i in range(num):
        with open("{}.{}".format(base_path, i)) as f:
            content = f.read()
        
        bias_maps.append(json.loads(content))

    return merge_rc4_bias_maps(bias_maps)



def merge_rc4_bias_maps(bias_maps):
    merged_map = [{} for i in range(256)]

    for bias_map in bias_maps:
        for i,_ in enumerate(bias_map):
            for k,v in bias_map[i]:
                if k in merged_map[i]:
                    merged_map[i][k] += v
                else:
                    merged_map[i][k] = v

    for i,_ in enumerate(merged_map):
        merged_map[i] = sorted(merged_map[i].items(), key=lambda kv: kv[1], reverse=True)

    return merged_map