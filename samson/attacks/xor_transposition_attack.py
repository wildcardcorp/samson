from samson.utilities.bytes import Bytes
from samson.analyzers.analyzer import Analyzer
from copy import deepcopy
import struct

import logging
log = logging.getLogger(__name__)

class XORTranspositionAttack(object):
    """
    Performs a plaintext recovery attack.

    Using only an Analyzer, attempts to break a many-time pad using structural properties.
    This attack has two phases:
        * Transposition analysis - creates a matrix out of the bytes and transposes it so the rows share a common keystream byte before analyzing it. WARNING: the ciphertexts are trimmed to the length of the smallest sample.
        
        * Full-text analysis - reverts the transposed matrix and then copies the new, partial plaintexts over the original ciphertexts. Each ciphertext is analyzed in its entirety and the best character per position is chosen. This process can be repeated to incrementally recover more plaintext.
    
    Conditions:
        * A stream/OTP-like cipher is used. I.E. plaintext XOR keystream
        * The user has collected more than one ciphertext using the same keystream.
    """

    def __init__(self, analyzer: Analyzer):
        """
        Parameters:
            analyzer (Analyzer): Analyzer that correctly scores the underlying plaintext.
        """
        self.analyzer = analyzer


    def execute(self, ciphertexts: list, iterations: int=3) -> list:
        """
        Executes the attack.
        
        Parameters:
            ciphertexts (list): List of bytes-like ciphertexts using the same keystream.
            iterations   (int): Number of iterations of the full-text analysis phase. Accuracy-time trade-off.

        Returns:
            list: List of recovered plaintexts.
        """
        min_size = min([len(ciphertext) for ciphertext in ciphertexts])

        same_size_ciphers = [ciphertext[:min_size] for ciphertext in ciphertexts]
        transposed_ciphers = [bytearray(transposed) for transposed in zip(*same_size_ciphers)]
        assert [bytearray(transposed) for transposed in zip(*transposed_ciphers)] == same_size_ciphers

        log.debug("Starting initial transposition analysis")

        # Transposition analysis first (transposition)
        transposed_plaintexts = []
        for cipher in transposed_ciphers:
            all_chars = {}
            for char in range(256):
                plaintext = Bytes(struct.pack('B', char)).stretch(len(cipher)) ^ cipher

                all_chars[char] = (self.analyzer.analyze(plaintext), plaintext)

            transposed_plaintexts.append(sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1])


        retransposed_plaintexts = [bytearray(transposed) for transposed in zip(*transposed_plaintexts)]

        log.debug("Starting full-text analysis on retransposed text")

        # Clean up with a character-by-character, higher-context analysis (retransposed)
        for j in range(iterations):
            log.debug("Starting iteration {}/{}".format(j + 1, iterations))
            differential_mask = bytearray()

            for i in range(min_size):
                all_chars = {}

                for char in range(256):
                    full_text_analyses = []

                    frames = []
                    for curr_cipher in retransposed_plaintexts:
                        cipher_copy = deepcopy(curr_cipher)
                        cipher_copy[i] = ord(Bytes(struct.pack('B', char)) ^ struct.pack('B', curr_cipher[i]))

                        preprocessed_frame = self.analyzer.preprocess(cipher_copy)
                        frames.append(preprocessed_frame)
                        full_text_analyses.append(self.analyzer.analyze(cipher_copy))

                    all_chars[char] = (sum(full_text_analyses), char)

                best_char = sorted(all_chars.items(), key=lambda kv: kv[1][0], reverse=True)[0][1][1]
                differential_mask += struct.pack('B', best_char)

            retransposed_plaintexts = [Bytes.wrap(cipher) ^ differential_mask for cipher in retransposed_plaintexts]

        return retransposed_plaintexts
