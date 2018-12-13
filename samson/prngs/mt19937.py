#!/usr/bin/python3
w, n, m, r = (32, 624, 397, 31)
a = 0x9908b0df
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
def _untemper_right(y, bits):
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


def _untemper_left(y, bits, constant):
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


def _untemper(y):
    y = _untemper_right(y, l)
    y = _untemper_left(y, t, c)
    y = _untemper_left(y, s, b)
    y = _untemper_right(y, u)
    return y & d



# Implementation of MT19937
class MT19937:
    """
    Mersenne Twister 19937
    """

    def __init__(self, seed: int=0):
        """
        Parameters:
            seed (int): Initial value.
        """
        self.state = [0] * n
        self.seed = seed

        # Seed the algo
        self.index = n
        self.state[0] = seed

        for i in range(1, n):
            self.state[i] = asint32(f * (self.state[i - 1] ^ self.state[i - 1] >> (w - 2)) + i)


    def __repr__(self):
        return f"<MT19937: seed={self.seed}, index={self.index}, state={self.state}>"


    def __str__(self):
        return self.__repr__()


    def twist(self):
        """
        Called internally. Performs the `twist` operation of the Mersenne Twister.
        """
        for i in range(n):
            y = asint32((self.state[i] & 0x80000000) + (self.state[(i + 1) % n] & 0x7fffffff))
            self.state[i] = self.state[(i + m) % n] ^ y >> 1

            if y & 1 == 1:
                self.state[i] ^= a

        self.index = 0


    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        if self.index >= n:
            self.twist()

        y = self.state[self.index]
        y  = temper(y)

        self.index += 1

        return asint32(y)


    @staticmethod
    def crack(observed_outputs: list):
        """
        Given 624 observed, consecutive outputs, cracks the internal state of the original and returns a replica.

        Parameters:
            observed_outputs (list): List of consecutive inputs (in order, obviously).

        Returns:
            MT19937: A replica of the original MT19937.
        """
        if len(observed_outputs) < 624:
            raise ValueError("`observed_outputs` must contain at least 624 consecutive outputs.")

        cloned = MT19937(0)
        cloned.state = [_untemper(output) for output in observed_outputs][-624:]

        return cloned
