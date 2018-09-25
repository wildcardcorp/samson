from samson.prngs.mt19937 import MT19937

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


u, d = (11, 0xFFFFFFFF)
s, b = (7, 0x9D2C5680)
t, c = (15, 0xEFC60000)
l = 18

def _untemper(y):
    y = _untemper_right(y, l)
    y = _untemper_left(y, t, c)
    y = _untemper_left(y, s, b)
    y = _untemper_right(y, u)
    return y & d



class MT19937CloneAttack(object):
    def __init__(self):
        pass

    def execute(self, outputs):
        cloned = MT19937(0)
        cloned.state = [_untemper(output) for output in outputs][-624:]

        return cloned