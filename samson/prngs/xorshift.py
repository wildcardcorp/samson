# https://en.wikipedia.org/wiki/Xorshift

MASK32 = 0xFFFFFFFF
MASK58 = 0x3FFFFFFFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

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
    def __init__(self, seed: tuple):
        """
        Parameters:
            seed (tuple): Initial value.
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



class Xorshift116Plus(object):
    def __init__(self, seed: tuple):
        """
        Parameters:
            seed (tuple): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift116Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        state = self.state
        s1, s0 = state
        state[0] = s0

        s1 ^= (s1 << 24) & MASK58
        state[1] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 41)

        return (state[1] + s0) & MASK58



class Xorshift128Plus(object):
    def __init__(self, seed: tuple):
        """
        Parameters:
            seed (tuple): Initial value.
        """
        self.state = seed


    def __repr__(self):
        return f"<Xorshift128Plus: state={self.state}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        state = self.state
        s1, s0 = state
        state[0] = s0

        s1 ^= (s1 << 23) & MASK64
        s1 ^= s1 >> 17
        s1 ^= s0
        s1 ^= s0 >> 26

        state[1] = s1

        return sum(state) & MASK64



class Xorshift1024Star(object):
    def __init__(self, seed: tuple):
        """
        Parameters:
            seed (tuple): Initial value.
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
