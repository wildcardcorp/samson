from samson.prngs.xorshift import DEFAULT_SHFT_R, MASK32
from samson.prngs.iterative_prng import IterativePRNG

# https://github.com/XMPPwocky/nodebeefcl/blob/master/beef.py
# https://github.com/v8/v8/blob/ceade6cf239e0773213d53d55c36b19231c820b5/src/js/math.js#L143
# https://v8.dev/blog/math-random <-- Looks to be wrong
# http://www.helsbreth.org/random/rng_mwc1616.html
class MWC1616(IterativePRNG):
    """
    Multyply-with-carry 1616
    """

    NATIVE_BITS = 32
    STATE_SIZE  =  2

    def __init__(self, seed: (int, int), a: int=18030, b: int=30903):
        """
        Parameters:
            seed ((int, int)): An integer or two-tuple of integers. If just an integer, it will be split into two.
            a           (int): Multiplier for the state's first item.
            b           (int): Multiplier for the state's second item.
        """
        if type(seed) == int:
            seed = ((seed >> 16) & 0xFFFF, seed & 0xFFFF)

        self.state = seed
        self.a = a
        self.b = b


    def __repr__(self):
        return f"<MWC1616: state={self.state}, a={self.a}, b={self.b}>"

    def __str__(self):
        return self.__repr__()



    # @staticmethod
    def gen_func(self, sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK32, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        sym_s0 = (self.a * (sym_s0 & 0xFFFF) + SHFT_R(sym_s0, 16)) & MASK32
        sym_s1 = (self.b * (sym_s1 & 0xFFFF) + SHFT_R(sym_s1, 16)) & MASK32

        return (sym_s0, sym_s1), (SHFT_L(sym_s0, 16) + (sym_s1 & 0xFFFF)) & MASK32




    # def generate(self) -> int:
    #     """
    #     Generates the next psuedorandom output.

    #     Returns:
    #         int: Next psuedorandom output.
    #     """
    #     s0, s1 = self.state
    #     s0 = (self.a * (s0 & 0xFFFF) + (s0 >> 16)) & MASK32
    #     s1 = (self.b * (s1 & 0xFFFF) + (s1 >> 16)) & MASK32

    #     self.state = (s0, s1)

    #     return ((s0 << 16) + (s1 & 0xFFFF)) & MASK32
