from samson.utilities.manipulation import left_rotate, right_rotate, unxorshift_left
from samson.prngs.xorshift import DEFAULT_SHFT_R
from samson.core.iterative_prng import IterativePRNG, CrackingDifficulty

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

class Xoshiro128PlusPlus(IterativePRNG):
    """
    References:
        http://prng.di.unimi.it/xoshiro128plusplus.c
    """
    NATIVE_BITS = 32
    STATE_SIZE  = 4
    CRACKING_DIFFICULTY = CrackingDifficulty.EXTREME


    @staticmethod
    def gen_func(sym_s0, sym_s1, sym_s2, sym_s3, SHFT_L=lambda x, n: (x << n) & MASK32, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x, n: left_rotate(x, n, bits=32)) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s0, s1, s2, s3 = [s & MASK32 for s in [sym_s0, sym_s1, sym_s2, sym_s3]]
        result = RotateLeft(s0 + s3, 7) + s0

        t   = SHFT_L(s1, 9)
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3

        s2 ^= t
        s3  = RotateLeft(s3, 11)

        return [s0, s1, s2, s3], result & MASK32


    def reverse_clock(self) -> int:
        """
        Generates the previous pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        s0s, s1s, s2t, s3r = self.state

        for _ in range(2):
            s3s = right_rotate(s3r, 11, 32)
            s0  = s0s ^ s3s
            s1t = s2t ^ s1s
            s1  = unxorshift_left(s1t, 9, 32)
            s3  = s3s ^ s1
            t   = s1t ^ s1
            s2  = s2t ^ s0 ^ t

            s0s, s1s, s2t, s3r = s0, s1, s2, s3

        self.state = [s0, s1, s2, s3]

        return self.generate()



class Xoshiro256PlusPlus(IterativePRNG):
    """
    References:
        http://prng.di.unimi.it/xoshiro256plusplus.c
    """
    NATIVE_BITS = 64
    STATE_SIZE  = 4
    CRACKING_DIFFICULTY = CrackingDifficulty.EXTREME


    @staticmethod
    def gen_func(sym_s0, sym_s1, sym_s2, sym_s3, SHFT_L=lambda x, n: (x << n) & MASK64, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x, n: left_rotate(x, n, bits=64)) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s0, s1, s2, s3 = [s & MASK64 for s in [sym_s0, sym_s1, sym_s2, sym_s3]]
        result = RotateLeft(s0 + s3, 23) + s0

        t   = SHFT_L(s1, 17)
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3

        s2 ^= t
        s3  = RotateLeft(s3, 45)

        return [s0, s1, s2, s3], result & MASK64


    def reverse_clock(self) -> int:
        """
        Generates the previous pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        s0s, s1s, s2t, s3r = self.state

        for _ in range(2):
            s3s = right_rotate(s3r, 45, 64)
            s0  = s0s ^ s3s
            s1t = s2t ^ s1s
            s1  = unxorshift_left(s1t, 17, 64)
            s3  = s3s ^ s1
            t   = s1t ^ s1
            s2  = s2t ^ s0 ^ t

            s0s, s1s, s2t, s3r = s0, s1, s2, s3

        self.state = [s0, s1, s2, s3]

        return self.generate()
