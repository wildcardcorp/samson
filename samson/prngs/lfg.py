from samson.utilities.exceptions import SearchspaceExhaustedException
from samson.core.base_object import BaseObject
from samson.core.metadata import CrackingDifficulty
from types import FunctionType
from copy import deepcopy

def _gen_mask_op(mask):
    return lambda n: n & mask

class LFG(BaseObject):
    """
    Lagged Fibonacci generator
    """
    CRACKING_DIFFICULTY = CrackingDifficulty.TRIVIAL

    ADD_OP = lambda a, b: a + b
    SUB_OP = lambda a, b: a - b

    GEN_MASK_OP = _gen_mask_op

    @staticmethod
    def C_SHARP_MASK_OP(n):
        if n == 2147483647:
            return n-1
        elif n < 0:
            return n + 2147483647
        else:
            return n


    def __init__(self, state: list, tap: int, feed: int, operation: FunctionType=ADD_OP, increment: bool=False, mask_op: FunctionType=_gen_mask_op(0xFFFFFFFFFFFFFFFF), length: int=None):
        """
        Parameters:
            state     (list): Initial state.
            tap        (int): Initial tap position.
            feed       (int): Initial feed position.
            operation  (int): The operation the LFG performs. Function that takes in an integer and returns an integer.
            increment (bool): Whether to increment (True) or decrement (False) the feed and tap.
            mask_op   (func): Mask operation to use for integer operations.
            length     (int): Length of internal state.
        """
        self.state     = deepcopy(state)
        self.tap       = tap
        self.feed      = feed
        self.operation = operation
        self.increment = increment
        self.shift_mod = -1 + 2 * increment
        self.mask_op   = mask_op
        self.length    = length or len(state)


    def generate(self) -> int:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        self.tap  = (self.tap + self.shift_mod) % self.length
        self.feed = (self.feed + self.shift_mod) % self.length

        x = self.mask_op(self.operation(self.state[self.feed], self.state[self.tap]))
        self.state[self.feed] = x
        return x



    def reverse_clock(self) -> int:
        """
        Runs the algorithm backwards.

        Returns:
            int: Previous pseudorandom output.
        """
        x = self.mask_op(self.operation(self.state[self.feed], -self.state[self.tap]))
        self.state[self.feed] = x

        self.tap  = (self.tap  - self.shift_mod) % self.length
        self.feed = (self.feed - self.shift_mod) % self.length

        return self.state[self.feed]


    def crack(self, outputs: list, num_outputs_to_predict: int=2):
        """
        Cracks the full state of the LFG. NOTE: this function is NOT guaranteed to find the exact state. Instead, it finds an equivalent state.

        Parameters:
            outputs               (list): Observed outputs.
            num_outputs_to_predict (int): Number of outputs we reserve for prediction. Taking too many compared to the state length can cause issues (i.e. taking 2 when the state length is 3 will not work).
        """
        assert len(outputs) > self.length

        # We don't need all of the outputs (it can actually cause problems). We just have to synchronize at the end.
        orig_len = len(outputs)
        outputs = outputs[:self.length + num_outputs_to_predict]

        init_state  = outputs[:self.length][::self.shift_mod]
        next_states = outputs[self.length:][::self.shift_mod]

        next_state_len = len(next_states)

        lfg       = deepcopy(self)
        lfg.state = init_state

        for i in range(lfg.length):
            guessed_feed = (lfg.feed + lfg.shift_mod * i) % lfg.length
            guessed_tap  = (lfg.tap  + lfg.shift_mod * i) % lfg.length

            simulated_states = [lfg.mask_op(lfg.operation(lfg.state[(guessed_feed - lfg.shift_mod * j) % lfg.length], lfg.state[(guessed_tap - lfg.shift_mod * j) % lfg.length])) for j in range(next_state_len)][::-lfg.shift_mod]

            if simulated_states == next_states:
                # We've found working tap/feed positions. Run the clock difference to synchronize states.
                clock_difference = orig_len - len(outputs)
                lfg.feed = (guessed_feed - lfg.shift_mod * next_state_len) % lfg.length
                lfg.tap  = (guessed_tap  - lfg.shift_mod * next_state_len) % lfg.length

                [lfg.generate() for _ in range(next_state_len + clock_difference)]
                return lfg

        raise SearchspaceExhaustedException('Unable to find correct tap and feed values.')
