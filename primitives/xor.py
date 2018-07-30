from samson.utilities import hamming_distance, xor_buffs, stretch_key
import operator

def decrypt(key, in_bytes):
    plaintext = xor_buffs(in_bytes, stretch_key(key, len(in_bytes)))
    return plaintext


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