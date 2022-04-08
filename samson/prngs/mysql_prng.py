from samson.core.primitives import BasePRNG
from samson.core.metadata import CrackingDifficulty, SizeSpec, SizeType
from samson.math.general import crt


transitions = {6: 0, 5: 1, 4: 2, 3: 3, 2: 4, 1: 5, 0: 6, 8: 7, 7: 8}

class MySQLPRNG(BasePRNG):
    """
    References:
        https://github.com/mysql/mysql-server/blob/3e90d07c3578e4da39dc1bce73559bbdf655c28c/mysys/my_rnd.cc#L50
    """

    CRACKING_DIFFICULTY = CrackingDifficulty.TRIVIAL
    NATIVE_BITS         = 30
    REQUIRED_SAMPLES    = SizeSpec(size_type=SizeType.SINGLE, sizes=2)

    def __init__(self, state: tuple, increment: int=33, modulus: int=2**30-1):
        self.state     = state
        self.increment = increment
        self.modulus   = modulus
    

    def generate(self) -> int:
        a,b = self.state
        a1 = (a*3 + b) % self.modulus
        b1 = (a1 + b + 33) % self.modulus
        self.state = (a1, b1)
        return a1


    def generate_double(self) -> float:
        return self.generate() / self.modulus


    def __reconstruct_a0(self, a1, b0):
        m9 = self.modulus // 9
        z  = (a1-b0)
        y  = z // 3
        return crt([(transitions[a1 % 9], 9), (y % m9, m9)])[0]


    def reverse_clock(self) -> int:
        a1, b1 = self.state
        b0 = (b1 - a1 - 33) % self.modulus

        a0 = self.__reconstruct_a0(a1, b0)

        self.state = (a0, b0)
        return a0


    def crack(self, outputs):
        a1, a2 = outputs[-2:]
        b0 = a2 - 4*a1 -33
        a0 = self.__reconstruct_a0(a1, b0)

        prng = self.copy()
        prng.state = (a0, b0)
        [prng.generate() for _ in range(2)]
        return prng
