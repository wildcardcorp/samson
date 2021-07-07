from samson.prngs.xorshift import DEFAULT_SHFT_R, MASK32, MASK64
from samson.core.iterative_prng import IterativePRNG, CrackingDifficulty

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
    MASK        = MASK32
    HALF_SIZE   = 16
    HALF_MASK   = 0xFFFF

    CRACKING_DIFFICULTY = CrackingDifficulty.EXPENSIVE

    def __init__(self, seed: (int, int), a: int=18030, b: int=30903):
        """
        Parameters:
            seed ((int, int)): An integer or two-tuple of integers. If just an integer, it will be split into two.
            a           (int): Multiplier for the state's first item.
            b           (int): Multiplier for the state's second item.
        """
        if type(seed) == int:
            seed = ((seed >> self.HALF_SIZE) & self.HALF_MASK, seed & self.HALF_MASK)

        super().__init__(seed)
        self.a = a
        self.b = b


    def gen_func(self, sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK32, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        sym_s0 = (self.a * (sym_s0 & self.HALF_MASK) + SHFT_R(sym_s0, self.HALF_SIZE)) & self.MASK
        sym_s1 = (self.b * (sym_s1 & self.HALF_MASK) + SHFT_R(sym_s1, self.HALF_SIZE)) & self.MASK

        return (sym_s0, sym_s1), (SHFT_L(sym_s0, self.HALF_SIZE) + (sym_s1 & self.HALF_MASK)) & self.MASK


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        sym_s0, sym_s1 = self.state

        for _ in range(2):
            s0_r, s0_q = divmod(sym_s0, self.a)
            s1_r, s1_q = divmod(sym_s1, self.b)

            s0 = (s0_q << self.HALF_SIZE) + s0_r
            s1 = (s1_q << self.HALF_SIZE) + s1_r

            sym_s0, sym_s1 = s0, s1

        self.state = [sym_s0, sym_s1]

        return self.generate()



class MWC(IterativePRNG):
    """
    Multyply-with-carry 1616
    """

    NATIVE_BITS = 64
    STATE_SIZE  =  2
    MASK        = MASK64
    HALF_SIZE   = 32
    HALF_MASK   = MASK32

    CRACKING_DIFFICULTY = CrackingDifficulty.EXPENSIVE

    def __init__(self, seed: ((int, int)), a: int=0xFFFFDA61):
        """
        Parameters:
            seed ((int, int)): An integer or two-tuple of integers. If just an integer, it will be split into two.
            a    (int): Multiplier for the state's first item.
        """
        if type(seed) == int:
            seed = ((seed >> self.HALF_SIZE) & self.HALF_MASK, seed & self.HALF_MASK)

        super().__init__(seed)
        self.a = a


    def gen_func(self, sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK32, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        S, carry = sym_s0, sym_s1
        state    = (self.a*S + carry) & self.MASK
        S, carry = state & self.HALF_MASK, state >> self.HALF_SIZE

        return (S, carry), S


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        S, carry = self.state

        for _ in range(2):
            state    = (carry << self.HALF_SIZE) + S
            S, carry = divmod(state, self.a)

        self.state = [S, carry]

        return self.generate()
