from samson.utilities.manipulation import left_rotate
from samson.prngs.xorshift import DEFAULT_SHFT_R
from samson.core.iterative_prng import IterativePRNG

MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

class Xoroshiro116Plus(IterativePRNG):
    NATIVE_BITS = 58
    STATE_SIZE  =  2

    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xoroshiro116Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def gen_func(sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK58, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x, n: left_rotate(x, n, bits=58)) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s0, s1 = sym_s0, sym_s1
        result = (s0 + s1) & MASK58

        s1 ^= s0
        sym_s0 = RotateLeft(s0, 24) ^ s1 ^ SHFT_L(s1, 2)
        sym_s1 = RotateLeft(s1, 35)
        return [sym_s0, sym_s1], result



class Xoroshiro128Plus(IterativePRNG):
    NATIVE_BITS = 64
    STATE_SIZE  =  2

    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xoroshiro128Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def gen_func(sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK64, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x, n: left_rotate(x, n, bits=64)) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s0, s1 = sym_s0, sym_s1
        result = (s0 + s1) & MASK64

        s1 ^= s0
        sym_s0 = RotateLeft(s0, 24) ^ s1 ^ SHFT_L(s1, 16)
        sym_s1 = RotateLeft(s1, 37)
        return [sym_s0, sym_s1], result
