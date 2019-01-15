from samson.utilities.manipulation import left_rotate
from types import FunctionType

MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

class Xoroshiro(object):
    def __init__(self, seed: tuple):
        """
        Parameters:
            seed (tuple): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xoroshiro: state={self.state}>"

    def __str__(self):
        return self.__repr__()



class Xoroshiro116Plus(Xoroshiro):
    def __repr__(self):
        return f"<Xoroshiro116Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()

    
    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        s0, s1 = self.state
        result = (s0 + s1) & MASK58

        s1 ^= s0
        self.state[0] = left_rotate(s0, 24, bits=58) ^ s1 ^ ((s1 << 2) & MASK58)
        self.state[1] = left_rotate(s1, 35, bits=58)
        return result



class Xoroshiro128Plus(Xoroshiro):
    def __repr__(self):
        return f"<Xoroshiro128Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()

    
    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        s0, s1 = self.state
        result = (s0 + s1) & MASK64

        s1 ^= s0
        self.state[0] = left_rotate(s0, 24, bits=64) ^ s1 ^ ((s1 << 16) & MASK64)
        self.state[1] = left_rotate(s1, 37, bits=64)
        return result