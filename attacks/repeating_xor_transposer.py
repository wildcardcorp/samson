from samson.utilities import *
from samson.primitives.xor import find_key_size
import base64

class RepeatingXORTransposer(object):
    def __init__(self, analyzer, decryptor):
        self.analyzer = analyzer
        self.decryptor = decryptor

    def execute(self, ciphertexts):
        possible_key_sizes = find_key_size(ciphertexts, range(2, 40), 5)
        top_candidates = []
        
        for size, distance in possible_key_sizes:
            key = b""
            success = True
            for block in transpose(ciphertexts, size):
                candidates = self.analyzer.build_candidates(block, 8)
                if len(candidates) > 0:
                    key += candidates[0][0]
                else:
                    success = False
                    break
            if success:
                top_candidates.append(key)


        final_candidates = sorted(top_candidates, key=lambda x: self.analyzer.analyze(self.decryptor(ciphertexts, x)), reverse=True)[:3]

        return final_candidates, self.decryptor(final_candidates[0], ciphertexts)