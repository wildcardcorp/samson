from samson.core.iterative_prng import IterativePRNG, CrackingDifficulty
from samson.core.base_object import BaseObject
from samson.utilities.manipulation import unxorshift_left, unxorshift_right
from samson.utilities.exceptions import NoSolutionException
from samson.math.algebra.rings.integer_ring import ZZ

# https://en.wikipedia.org/wiki/Xorshift

MASK32 = 0xFFFFFFFF
MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

DEFAULT_SHFT_R = lambda x, n: x >> n


class Xorshift32(IterativePRNG):
    NATIVE_BITS = 32
    STATE_SIZE  =  1


    @staticmethod
    def gen_func(sym_s0, SHFT_L=lambda x, n: (x << n) & MASK32, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        x  = sym_s0
        x ^= SHFT_L(x, 13)
        x ^= SHFT_R(x, 17)
        x ^= SHFT_L(x,  5)
        sym_s0 = x

        return [sym_s0], sym_s0


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        x = self.state[0]
        x = unxorshift_left(x, 5, self.NATIVE_BITS)
        x = unxorshift_right(x, 17, self.NATIVE_BITS)
        x = unxorshift_left(x, 13, self.NATIVE_BITS)
        self.state = [x]
        return x


class Xorshift64(IterativePRNG):
    NATIVE_BITS = 64
    STATE_SIZE  =  1


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


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        x = self.state[0]
        x = unxorshift_left(x, 17, self.NATIVE_BITS)
        x = unxorshift_right(x, 7, self.NATIVE_BITS)
        x = unxorshift_left(x, 13, self.NATIVE_BITS)
        self.state = [x]
        return x


class Xorshift128(IterativePRNG):
    NATIVE_BITS = 64
    STATE_SIZE  =  4


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


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        t, s1, s2, s3 = self.state
        t ^= s1 ^ DEFAULT_SHFT_R(s1, 19)
        s0, s1, s2 = s1, s2, s3
        t = unxorshift_right(t, 8, self.NATIVE_BITS)
        t = unxorshift_left(t, 11, self.NATIVE_BITS)
        self.state = [s0, s1, s2, t]
        return s0



class Xorshift116Plus(IterativePRNG):
    NATIVE_BITS = 58
    STATE_SIZE  =  2


    @staticmethod
    def gen_func(sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK58, SHFT_R=DEFAULT_SHFT_R, RotateLeft=lambda x:x) -> (list, int):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s1, s0 = sym_s0, sym_s1

        s1 ^= SHFT_L(s1, 24)
        s1 ^= s0 ^ SHFT_R(s1, 11) ^ SHFT_R(s0, 41)

        return [s0, s1], (s1 + s0) & MASK58


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        s0, s1 = self.state
        s1 ^= s0 ^ DEFAULT_SHFT_R(s0, 41)
        s1  = unxorshift_right(s1, 11, self.NATIVE_BITS)
        s1  = unxorshift_left(s1, 24, self.NATIVE_BITS)
        self.state = [s0, s1]
        return (s1 + s0) & MASK58


# Reference: https://github.com/TACIXAT/XorShift128Plus/blob/master/xs128p.py
class Xorshift128Plus(IterativePRNG):
    NATIVE_BITS = 64
    STATE_SIZE  =  2


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
            int: Previous pseudorandom output.
        """
        s0, s1 = self.state
        prev_state1 = s0
        prev_state0 = s1 ^ (s0 >> 26)
        prev_state0 = prev_state0 ^ s0
        prev_state0 = unxorshift_right(prev_state0, 17, self.NATIVE_BITS)
        prev_state0 = unxorshift_right(prev_state0, 23, self.NATIVE_BITS)
        self.state  = [prev_state0, prev_state1]

        return sum(self.state) & MASK64



class Xorshift1024Star(BaseObject):
    NATIVE_BITS = 64
    STATE_SIZE  = 16
    CRACKING_DIFFICULTY = CrackingDifficulty.TRIVIAL


    def __init__(self, seed: list, p: int=0):
        """
        Parameters:
            seed (list): Initial value.
            p     (int): Initial array pointer.
        """
        self.state = [p, *seed]


    def generate(self) -> int:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        p  = self.state[0]
        s  = self.state[1:]
        s0 = s[p]

        p  = (p + 1) & 15
        s1 = s[p]

        s1  ^= (s1 << 31) & MASK64
        s[p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30)
        self.state = [p, *s]
        return (s[p] * 1181783497276652981) & MASK64


    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        p   = self.state[0]
        s   = self.state[1:]
        p_1 = (p-1) & 15

        s0 = s[p_1]
        s1 = s[p] ^ s0 ^ (s0 >> 30)
        s1 = unxorshift_right(s1, 11, self.NATIVE_BITS)
        s1 = unxorshift_left(s1, 31, self.NATIVE_BITS)

        s[p] = s1
        self.state = [p_1, *s]

        return (s0 * 1181783497276652981) & MASK64



    def crack(self, outputs: list):
        if len(outputs) < 17:
            raise ValueError('Not enough samples')

        samples   = outputs[:16]
        next_outs = outputs[16:]

        R     = ZZ/ZZ(2**64)
        inv_a = ~R(1181783497276652981)
        state = [int(R(o)*inv_a) for o in samples]

        # Search for the correct offset
        for offset in range(16):
            prng = Xorshift1024Star(state[offset:] + state[:offset])
            if [prng.generate() for _ in range(len(next_outs))] == next_outs:
                return prng

        raise NoSolutionException('No solution for samples')
