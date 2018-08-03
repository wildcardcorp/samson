from samson.oracles.padding_oracle import PaddingOracle
from samson.primitives.rsa import RSA
from samson.utilities import pkcs15_pad, int_to_bytes
from random import randint

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


class PKCS15PaddingOracleAttack(object):
    def __init__(self, oracle):
        self.oracle = oracle


    
    def execute(self, c, n, e, key_length):
        key_byte_len = key_length // 8
        # Convenience variables
        B = 2 ** (8 * (key_byte_len - 2))
        # n, e = rsa.n, rsa.e

        # Initial values
        c_0 = c
        M = [(2*B, 3*B - 1)]
        i = 1

        if not self.oracle.check_padding(c):
            # Step 1: Blinding
            while True:
                s = randint(0, n - 1)
                c_0 = (c * pow(s, e, n)) % n

                if self.oracle.check_padding(c_0):
                    break

        # Step 2
        while True:
            # Step 2.a
            if i == 1:
                s = _ceil(n, 3*B)

                while True:
                    c = c_0 * pow(s, e, n) % n
                    if self.oracle.check_padding(c):
                        break

                    s += 1
            # Step 2.b
            elif len(M) >= 2:
                while True:
                    s += 1
                    c = c_0 * pow(s, e, n) % n

                    if self.oracle.check_padding(c):
                        break
                        
            # Step 2.c
            elif len(M) == 1:
                a, b = M[0]

                if a == b:
                    #b'\x00' + 
                    return b'\x00' + int_to_bytes(a, 'big')

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