from samson.utilities.manipulation import left_rotate
from types import FunctionType

MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

def V116_PLUS(x):
    s0, s1 = x
    result = (s0 + s1) & MASK58

    s1 ^= s0
    x[0] = left_rotate(s0, 24, bits=58) ^ s1 ^ ((s1 << 2) & MASK58)
    x[1] = left_rotate(s1, 35, bits=58)
    return x, result


# Might be correct for V128.
# def V128(x):
#     s0, s1 = x
#     result = (s0 + s1) & MASK64

#     s1 ^= s0
#     x[0] = left_rotate(s0, 55, bits=64) ^ s1 ^ ((s1 << 14) & MASK64)
#     x[1] = left_rotate(s1, 36, bits=64)
#     return x, result


def V128_PLUS(x):
    s0, s1 = x
    result = (s0 + s1) & MASK64

    s1 ^= s0
    x[0] = left_rotate(s0, 24, bits=64) ^ s1 ^ ((s1 << 16) & MASK64)
    x[1] = left_rotate(s1, 37, bits=64)
    return x, result


class Xoroshiro(object):
    def __init__(self, seed: int, variant: FunctionType=V128_PLUS):
        """
        Parameters:
            seed       (int): Initial value.
            variant   (func): Xoroshiro variant. Function that takes in an integer and returns (new_state, output).
        """
        self.state = seed
        self.variant = variant

    def __repr__(self):
        return f"<Xoroshiro: state={self.state}, variant={self.variant}>"


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
