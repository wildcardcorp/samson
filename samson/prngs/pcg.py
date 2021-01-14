from samson.utilities.manipulation import right_rotate
from samson.core.base_object import BaseObject
from samson.math.general import mod_inv
from types import FunctionType

#V{output_size}_{state_size}_{transform}[.._{n_transforms}]
def V32_64_XSH_RR(x, mult, inc):
    count = x >> 59
    state = (x * mult + inc) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 18
    return state, right_rotate((x >> 27) & 0xFFFFFFFF, count)



# https://en.wikipedia.org/wiki/Permuted_congruential_generator
class PCG(BaseObject):
    def __init__(self, seed: int, multiplier: int, increment: int, variant: FunctionType=V32_64_XSH_RR):
        """
        Parameters:
            seed       (int): Initial value.
            multiplier (int): Multiplier.
            increment  (int): Increment.
            variant   (func): PCG variant. Function that takes in (state, multiplier, increment) and returns (new_state, output).
        """
        self.state = seed
        self.multiplier = multiplier
        self.increment = increment
        self.variant = variant



    def generate(self) -> int:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        self.state, result = self.variant(self.state, self.multiplier, self.increment)
        return result


    def reverse_clock(self) -> int:
        inv_mul = mod_inv(self.multiplier, 2**64)
        self.state = ((self.state - self.increment) * inv_mul) % 2**64
        self.state = ((self.state - self.increment) * inv_mul) % 2**64
        return self.generate()
