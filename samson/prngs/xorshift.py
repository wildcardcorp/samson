from z3 import *
import random

# https://en.wikipedia.org/wiki/Xorshift

MASK32 = 0xFFFFFFFF
MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

class Xorshift(object):
    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        s0, s1, result = self.gen_func(*self.state)
        self.state = [s0, s1]
        return result


    @classmethod
    def crack(cls, outputs):
        ostate0, ostate1 = BitVecs('ostate0 ostate1', cls.NATIVE_BITS)
        sym_state0, sym_state1 = ostate0, ostate1

        solver = Solver()
        conditions = []

        for output in outputs:
            sym_state0, sym_state1, calc = cls.gen_func(sym_state0, sym_state1, SHFT_L=lambda x, n: x << n, SHFT_R=LShR)

            condition = Bool('c%d' % int(random.random()))
            solver.add(Implies(condition, calc == int(output)))
            conditions += [condition]

        if solver.check(conditions) == sat:
            model = solver.model()
            xs = cls([model[ostate0].as_long(), model[ostate1].as_long()])
            [xs.generate() for _ in outputs]
            return xs
        else:
            raise RuntimeError('Model not satisfiable.')



class Xorshift32(object):
    def __init__(self, seed: int):
        """
        Parameters:
            seed (int): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift32: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        x = self.state
        x ^= (x << 13) & MASK32
        x ^= x >> 17
        x ^= (x << 5) & MASK32
        self.state = x

        return x



class Xorshift64(object):
    def __init__(self, seed: int):
        """
        Parameters:
            seed (int): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift64: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        x = self.state
        x ^= (x << 13) & MASK64
        x ^= x >> 7
        x ^= (x << 17) & MASK64
        self.state = x

        return x



class Xorshift128(object):
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


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        x = self.state
        s = x[0]
        t = x[3]
        t ^= (t << 11) & MASK64
        t ^= t >> 8

        x[3] = x[2]
        x[2] = x[1]
        x[1] = x[0]

        t ^= s >> 19
        t ^= s
        t &= MASK64

        self.state = [t, *x[1:]]

        return t



class Xorshift116Plus(Xorshift):
    NATIVE_BITS = 58

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
    def gen_func(sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK58, SHFT_R=lambda x, n: x >> n):
        """
        Internal function compatible with Python and symbolic execution.
        """
        s1, s0 = sym_s0, sym_s1

        s1 ^= SHFT_L(s1, 24)
        s1 ^= s0 ^ SHFT_R(s1, 11) ^ SHFT_R(s0, 41)

        return s0, s1, (s1 + s0) & MASK58


# Reference: https://github.com/TACIXAT/XorShift128Plus/blob/master/xs128p.py
class Xorshift128Plus(Xorshift):
    NATIVE_BITS = 64

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
    def gen_func(sym_s0, sym_s1, SHFT_L=lambda x, n: (x << n) & MASK64, SHFT_R=lambda x, n: x >> n):
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

        return sym_s0, sym_s1, calc & MASK64


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
        p, s = self.state
        s0 = s[p]

        p = (p + 1) & 15
        s1 = s[p]

        s1 ^= (s1 << 31) & MASK64
        s[p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30)
        self.state = [p, s]
        return (s[p] * 1181783497276652981) & MASK64
