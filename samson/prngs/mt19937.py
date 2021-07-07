from samson.core.base_object import BaseObject
from samson.core.metadata import CrackingDifficulty
from samson.utilities.bytes import Bytes

w, n, m, r = (32, 624, 397, 31)
MAGIC = 0x9908b0df
f = 1812433253
u, d = (11, 0xFFFFFFFF)
s, b = (7, 0x9D2C5680)
t, c = (15, 0xEFC60000)
l = 18


def asint32(integer):
    return integer & d

def temper(y):
    y ^= (y >> u)
    y ^= (y << s) & b
    y ^= (y << t) & c
    y ^= (y >> l)
    return y


# We don't have to include a constant since 32-bit Mersenne Twister doesn't
# use non-idempotent constants on its right shifts.
def untemper_right(y, bits):
    # Create a 32-bit mask with `bits` 1s at the beginning.
    # We'll shift this over the iterations to invert the temper.
    mask = (1 << bits) - 1 << 32 - bits
    shift_mod = 0

    while mask > 0:
        y ^= shift_mod

        # Get next `bits` bits of y
        # Ex: bits = 3, mask = '00011100000000000'
        # '100_010_00100100001' -> '000000_010_00000000'
        shift_mod = (y & mask) >> bits

        # Move mask right `bits` to select next bits to shift
        # Ex: bits = 3
        # 11100000000000000 -> 00011100000000000
        mask >>= bits
    return y


def untemper_left(y, bits, constant):
    int32_mask = 0xFFFFFFFF
    mask = (1 << bits) - 1
    shift_mod = 0

    while (mask & int32_mask) > 0:
        y ^= shift_mod & constant

        # Get next `bits` bits of y
        shift_mod = (y & mask) << bits

        # Move mask right `bits` to select next bits to shift
        mask <<= bits
    return y


def untemper(y):
    y = untemper_right(y, l)
    y = untemper_left(y, t, c)
    y = untemper_left(y, s, b)
    y = untemper_right(y, u)
    return y & d



# Implementation of MT19937
class MT19937(BaseObject):
    """
    Mersenne Twister 19937

    References:
        https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
    """

    CRACKING_DIFFICULTY = CrackingDifficulty.TRIVIAL

    def __init__(self, seed: int=0):
        """
        Parameters:
            seed (int): Initial value.
        """
        self.state = [0] * n
        self.seed  = seed

        # Seed the algo
        self.index = n
        self.state[0] = seed

        for i in range(1, n):
            self.state[i] = asint32(f * (self.state[i - 1] ^ self.state[i - 1] >> (w - 2)) + i)


    def __reprdir__(self):
        return ['seed', 'index', 'state']


    def twist(self):
        """
        Called internally. Performs the `twist` operation of the Mersenne Twister.
        """
        for i in range(n):
            y = asint32((self.state[i] & 0x80000000) + (self.state[(i + 1) % n] & 0x7fffffff))
            self.state[i] = self.state[(i + m) % n] ^ y >> 1

            if y & 1 == 1:
                self.state[i] ^= MAGIC

        self.index = 0


    def generate(self) -> int:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        if self.index >= n:
            self.twist()

        y = self.state[self.index]
        y = temper(y)

        self.index += 1

        return asint32(y)


    def untwist(self):
        for i in reversed(range(n)):
            tmp  = self.state[i]
            tmp ^= self.state[(i + m) % n]

            if (tmp & 0x80000000) == 0x80000000:
                tmp ^= MAGIC

            result = (tmp << 1) & 0x80000000
            tmp    = self.state[(i - 1 + n) % n]
            tmp   ^= self.state[(i - 1 + m) % n]

            if (tmp & 0x80000000) == 0x80000000:
                tmp    ^= MAGIC
                result |= 1

            result |= (tmp << 1) & 0x7fffffff
            self.state[i] = result

        self.index = n-1



    def reverse_clock(self) -> int:
        """
        Generates the previous pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        self.index -= 1
        if self.index < 0:
            self.untwist()

        y = self.state[self.index]
        y = temper(y)

        return asint32(y)



    @staticmethod
    def crack(observed_outputs: list) -> 'MT19937':
        """
        Given 624 observed, consecutive outputs, cracks the internal state of the original and returns a replica.

        Parameters:
            observed_outputs (list): List of consecutive inputs (in order, obviously).

        Returns:
            MT19937: A replica of the original MT19937.
        """
        if len(observed_outputs) < n:
            raise ValueError("`observed_outputs` must contain at least 624 consecutive outputs.")

        cloned = MT19937(0)
        cloned.state = [untemper(output) for output in observed_outputs][-n:]

        return cloned


    @staticmethod
    def init_by_array(init_key: list) -> 'MT19937':
        prng       = MT19937(19650218)
        mt         = prng.state
        key_length = len(init_key)

        i, j = 1, 0

        for k in reversed(range(max(key_length, n))):
            mt[i] = ((mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525)) + init_key[j] + j) % 2**32
            i += 1
            j += 1
            if i >= n:
                mt[0] = mt[n-1]
                i = 1

            if j >= key_length:
                j = 0

        for k in reversed(range(n-1)):
            mt[i] = ((mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941)) - i) % 2**32
            i += 1
            if i >= n:
                mt[0] = mt[n-1]
                i = 1

        mt[0] = 0x80000000
        prng.state = mt

        return prng


    @staticmethod
    def python_seed(seed: int) -> 'MT19937':
        return MT19937.init_by_array([b.change_byteorder().int() for b in Bytes(seed, 'little').pad_congruent_left(4).chunk(4)])
