from types import FunctionType

# https://en.wikipedia.org/wiki/Xorshift

MASK32 = 0xFFFFFFFF
MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

def V32(x):
    x ^= (x << 13) & MASK32
    x ^= x >> 17
    x ^= (x << 5) & MASK32

    return x, x


def V64(x):
    x ^= (x << 13) & MASK64
    x ^= x >> 7
    x ^= (x << 17) & MASK64

    return x, x


def V128(x):
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

    return [t, *x[1:]], t


def V116_PLUS(state):
    s1, s0 = state
    state[0] = s0

    s1 ^= (s1 << 24) & MASK58
    state[1] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 41)

    return state, (state[1] + s0) & MASK58



def V128_PLUS(state):
    s1, s0 = state
    state[0] = s0

    s1 ^= (s1 << 23) & MASK64
    s1 ^= s1 >> 17
    s1 ^= s0
    s1 ^= s0 >> 26

    state[1] = s1

    return state, sum(state) & MASK64



def V1024_STAR(state):
    p, s = state
    s0 = s[p]

    p = (p + 1) & 15
    s1 = s[p]

    s1 ^= (s1 << 31) & MASK64
    s[p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30)
    return [p, s], (s[p] * 1181783497276652981) & MASK64



class Xorshift(object):
    def __init__(self, seed: int, variant: FunctionType=V128_PLUS):
        """
        Parameters:
            seed       (int): Initial value.
            variant   (func): Xorshift variant. Function that takes in the current state (may be a list) and returns (new_state, output).
        """
        self.state = seed
        self.variant = variant

    def __repr__(self):
        return f"<Xorshift: state={self.state}, variant={self.variant}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        self.state, result = self.variant(self.state)
        return result
