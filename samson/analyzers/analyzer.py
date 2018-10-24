import itertools
import struct

class Analyzer(object):
    def __init__(self, attempt_key):
        self.attempt_key = attempt_key


    def analyze(self, in_bytes):
        pass


    def build_candidates(self, in_bytes, key_length):
        all_keys = itertools.product(range(2), repeat=key_length)
        candidates = []

        for key in all_keys:
            bin_key = b''
            for i in range(max(key_length // 8, 1)):
                bin_key += struct.pack('B', int(''.join([str(curr_int) for curr_int in key[i * 8: (i + 1) * 8]]), 2))

            #, is_readable
            plaintext = self.attempt_key(bin_key, in_bytes)

            candidates.append((bin_key, plaintext))
            # if is_readable:
            #     candidates.append((bin_key, plaintext))


        return sorted(candidates, key=lambda x: self.analyze(x[1]), reverse=True)


    def select_highest_scores(self, in_list, num=1):
        return sorted(in_list, key=lambda item: self.analyze(item), reverse=True)[:num]