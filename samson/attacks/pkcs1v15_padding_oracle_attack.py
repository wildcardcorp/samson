from samson.utilities.encoding import int_to_bytes
from samson.oracles.padding_oracle import PaddingOracle
from samson.utilities.bytes import Bytes
from random import randint

import logging
log = logging.getLogger(__name__)

def _ceil(a, b):
    return (a + b - 1) // b


def _append_and_merge(new_a, new_b, intervals):
    for i, (a, b) in enumerate(intervals):
        if not (b < new_a or a > new_b):
            new_a = min(a, new_a)
            new_b = max(b, new_b)
            intervals[i] = new_a, new_b
            return

    intervals.append((new_a, new_b))


class PKCS1v15PaddingOracleAttack(object):
    """
    Performs a plaintext recovery attack.

    The PKCS#1 v1.5 padding oracle attack found by Daniel Bleichenbacher is an adaptive chosen-plaintext attack that
    takes advantage of an information leak through the validation of the plaintext's padding. Using RSA's homomorphic
    properties, the algorithm can iteratively converge on the correct plaintext.

    Conditions:
        * RSA is being used
        * PKCS#1 v1.5 padding is being used
        * The user has access to an oracle that allows abitrary plaintext input and leaks whether the padding is correct.
    """

    def __init__(self, oracle: PaddingOracle):
        """
        Parameters:
            oracle (PaddingOracle): An oracle that takes in an integer and returns whether the padding is correct.
        """
        self.oracle = oracle



    def execute(self, ciphertext: int, n: int, e: int, key_length: int) -> Bytes:
        """
        Executes the attack.

        Parameters:
            ciphertext (int): The ciphertext represented as an integer.
                     n (int): The RSA instance's modulus.
                     e (int): The RSA instance's public exponent.
            key_length (int): The the bit length of the RSA instance (2048, 4096, etc).
        
        Returns:
            Bytes: The ciphertext's corresponding plaintext.
        """
        key_byte_len = key_length // 8

        # Convenience variables
        B = 2 ** (8 * (key_byte_len - 2))

        # Initial values
        c = ciphertext
        c_0 = ciphertext
        M = [(2*B, 3*B - 1)]
        i = 1

        if not self.oracle.check_padding(c):
            log.debug("Initial padding not correct; attempting blinding")

            # Step 1: Blinding
            while True:
                s = randint(0, n - 1)
                c_0 = (c * pow(s, e, n)) % n

                if self.oracle.check_padding(c_0):
                    log.debug("Padding is now correct; blinding complete")
                    break

        # Step 2
        while True:
            log.debug("Starting iteration {}".format(i))
            log.debug("Current intervals: {}".format(M))
            # Step 2.a
            if i == 1:
                s = _ceil(n, 3*B)

                log.debug("Starting search at {}".format(s))

                while True:
                    c = c_0 * pow(s, e, n) % n
                    if self.oracle.check_padding(c):
                        break

                    s += 1
            # Step 2.b
            elif len(M) >= 2:
                log.debug("Intervals left: {}".format(M))
                while True:
                    s += 1
                    c = c_0 * pow(s, e, n) % n

                    if self.oracle.check_padding(c):
                        break

            # Step 2.c
            elif len(M) == 1:
                log.debug("Only one interval")

                a, b = M[0]

                if a == b:
                    return Bytes(b'\x00' + int_to_bytes(a, 'big'))

                r = _ceil(2 * (b*s - 2*B), n)
                s = _ceil(2*B + r*n, b)

                while True:
                    c = c_0 * pow(s, e, n) % n
                    if self.oracle.check_padding(c):
                        break

                    s += 1
                    if s > (3*B + r*n) // a:
                        r += 1
                        s = _ceil(2*B + r*n, b)

            M_new = []

            for a, b in M:
                min_r = _ceil(a*s - 3*B + 1, n)
                max_r = (b*s - 2*B) // n

                for r in range(min_r, max_r + 1):
                    new_a = max(a, _ceil(2*B + r*n, s))
                    new_b = min(b, (3*B - 1 + r*n) // s)

                    if new_a > new_b:
                        raise Exception("Step 3: new_a > new_b? new_a: {} new_b: {}".format(new_a, new_b))


                    # Now we need to check for overlap between ranges and merge them
                    _append_and_merge(new_a, new_b, M_new)


            if len(M_new) == 0:
                raise Exception("There are zero intervals in 'M_new'")

            M = M_new
            i += 1
