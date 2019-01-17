from samson.prngs.iterative_prng import IterativePRNG

# https://en.wikipedia.org/wiki/Xorshift

MASK32 = 0xFFFFFFFF
MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

DEFAULT_SHFT_R = lambda x, n: x >> n


class Xorshift32(IterativePRNG):
    NATIVE_BITS = 32
    STATE_SIZE  =  1

    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift32: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def gen_func(sym_s0, SHFT_L=lambda x, n: (x << n) & MASK32, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        x = sym_s0
        x ^= SHFT_L(x, 13)
        x ^= SHFT_R(x, 17)
        x ^= SHFT_L(x,  5)
        sym_s0 = x

        return [sym_s0], sym_s0



class Xorshift64(IterativePRNG):
    NATIVE_BITS = 64
    STATE_SIZE  =  1

    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift64: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def gen_func(sym_s0, SHFT_L=lambda x, n: (x << n) & MASK64, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        x = sym_s0
        x ^= SHFT_L(x, 13)
        x ^= SHFT_R(x,  7)
        x ^= SHFT_L(x, 17)
        sym_s0 = x

        return [sym_s0], sym_s0



class Xorshift128(IterativePRNG):
    NATIVE_BITS = 64
    STATE_SIZE  =  4

    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift128: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def gen_func(sym_s0, sym_s1, sym_s2, sym_s3, SHFT_L=lambda x, n: (x << n) & MASK64, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s = sym_s0
        t = sym_s3
        t ^= SHFT_L(t, 11)
        t ^= SHFT_R(t,  8)

        sym_s3 = sym_s2
        sym_s2 = sym_s1
        sym_s1 = sym_s0

        t ^= SHFT_R(s, 19)
        t ^= s
        t &= MASK64

        return [t, sym_s1, sym_s2, sym_s3], t


class Xorshift116Plus(IterativePRNG):
    NATIVE_BITS = 58
    STATE_SIZE  =  2

    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift116Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def gen_func(sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK58, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s1, s0 = sym_s0, sym_s1

        s1 ^= SHFT_L(s1, 24)
        s1 ^= s0 ^ SHFT_R(s1, 11) ^ SHFT_R(s0, 41)

        return [s0, s1], (s1 + s0) & MASK58



# Reference: https://github.com/TACIXAT/XorShift128Plus/blob/master/xs128p.py
class Xorshift128Plus(IterativePRNG):
    NATIVE_BITS = 64
    STATE_SIZE  =  2

    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift128Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def gen_func(sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK64, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s1 = sym_s0
        s0 = sym_s1
        s1 ^= SHFT_L(s1, 23)
        s1 ^= SHFT_R(s1, 17)
        s1 ^= s0
        s1 ^= SHFT_R(s0, 26)
        sym_s0 = sym_s1
        sym_s1 = s1
        calc = (sym_s0 + sym_s1)

        return [sym_s0, sym_s1], calc & MASK64


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous psuedorandom output.
        """
        s0, s1 = self.state
        prev_state1 = s0
        prev_state0 = s1 ^ (s0 >> 26)
        prev_state0 = prev_state0 ^ s0
        prev_state0 = prev_state0 ^ (prev_state0 >> 17) ^ (prev_state0 >> 34) ^ (prev_state0 >> 51)
        prev_state0 = (prev_state0 ^ (prev_state0 << 23) ^ (prev_state0 << 46)) & 0xFFFFFFFFFFFFFFFF
        self.state = [prev_state0, prev_state1]

        return sum(self.state) & MASK64



class Xorshift1024Star(object):
    def __init__(self, seed: list):
        """
        Parameters:
            seed (list): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift1024Star: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        # p, s = self.state
        p = self.state[0]
        s = self.state[1:]
        s0 = s[p]

        p = (p + 1) & 15
        s1 = s[p]

        s1 ^= (s1 << 31) & MASK64
        s[p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30)
        self.state = [p, *s]
        return (s[p] * 1181783497276652981) & MASK64
