from samson.utilities.analysis import generate_rc4_bias_map, RC4_BIAS_MAP
import multiprocessing
import itertools
import struct

import logging
log = logging.getLogger(__name__)

# The RC4PrependAttack uses an EncryptionOracle that prepends the payload and then encrypts the whole message with a randomly generated key.
# The attack uses specific byte biases found in the RC4 keystream and feeds the plaintext into these locations. Using the law of large numbers,
# the keystream bias will surface, and we can XOR it with the ciphertext to return the plaintext. This specific implementation uses several optmizations.
# The first is concurrency/parallelism and is self-explanatory. The second is the use of concurrent biases. We first determine which biases we can still use
# in the attack. This is necessary since we can only feed the plaintext forward, so plaintext index five is not eligible to use RC4 bias index 2. Next, we determine
# which biases are "active". If the plaintext is 20 characters long, and the current padding position is 0, then we can utilize both RC4 bias indices 2 and 16 (i.e. 1 and 15 using a zero-based-index).
# Lastly, we introduce "branches". If a byte happens to decrypted more than one and has different outcomes, we keep both. At the end, we return the Cartesian product of all
# byte decryptions. This will normally just be one.

class RC4PrependAttack(object):
    # Takes an EncryptionOracle
    def __init__(self, oracle):
        self.oracle = oracle
        self.strongest_biases = [1, 15, 31]
        

    def _encrypt_chunk(self, payload, chunk_size):
        return [self.oracle.encrypt(payload) for _ in range(chunk_size)]


    def execute(self, ciphertext_length, sample_size=2**23):
        cracked_indices = [set()for i in range(ciphertext_length)]
        cpu_count = multiprocessing.cpu_count()
        pool = multiprocessing.Pool(processes=cpu_count)

        log.debug("Running with {} cores".format(cpu_count))

        for i in range(ciphertext_length):
            log.debug("Starting iteration {}/{}".format(i, ciphertext_length))

            if len(cracked_indices[i]) > 0:
                continue

            applicable_biases = [bias for bias in self.strongest_biases if i <= bias or (ciphertext_length + i >= bias and i < bias)]
            padding_len = max(applicable_biases[0] - i, 0)
            active_biases = [bias for bias in applicable_biases if padding_len + ciphertext_length > bias]

            payload = b'\x00' * padding_len
            chunk_size = sample_size // cpu_count

            log.debug("Sampling {} ciphertexts".format(sample_size))
            random_ciphertexts = [pool.apply_async(self._encrypt_chunk, (payload, chunk_size)) for i in range(cpu_count)]
            flattened_list = [result for result_list in random_ciphertexts for result in result_list.get()]

            log.debug("Generating bias map")
            bias_map = generate_rc4_bias_map(flattened_list)

            for bias_idx in active_biases:
                cracked_indices[bias_idx - padding_len].add(RC4_BIAS_MAP[bias_idx] ^ bias_map[bias_idx][0][0])


        all_branches = itertools.product(*[list(results) for results in cracked_indices])
        return [struct.pack('B' * len(branch), *branch) for branch in all_branches]