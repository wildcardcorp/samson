from types import FunctionType
from copy import deepcopy

class LFG(object):
    """
    Lagged Fibonacci generator
    """

    ADD_OP = lambda a, b: a + b
    SUB_OP = lambda a, b: a - b

    def __init__(self, state: list, tap: int, feed: int, length: int, operation: FunctionType=ADD_OP, increment: bool=False):
        """
        Parameters:
            state     (list): Initial state.
            tap        (int): Initial tap position.
            feed       (int): Initial feed position.
            length     (int): Length of internal state (modulus).
            operation  (int): The operation the LFG performs. Function that takes in an integer and returns an integer.
            increment (bool): Whether to increment (True) or decrement (False) the feed and tap.
        """
        self.state = deepcopy(state)
        self.tap = tap
        self.feed = feed
        self.length = length
        self.operation = operation
        self.increment = increment
        self.shift_mod = -1 + 2 * increment


    def __repr__(self):
        return f"<LFG: state={self.state}, tap={self.tap}, feed={self.feed}, length={self.length}, operation={self.operation}, increment={self.increment}>"

    def __str__(self):
        return self.__repr__()



    def generate(self) -> int:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        self.tap = (self.tap + self.shift_mod) % self.length
        self.feed = (self.feed + self.shift_mod) % self.length

        x = self.operation(self.state[self.feed], self.state[self.tap]) & 0xFFFFFFFFFFFFFFFF
        self.state[self.feed] = x
        return x



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

        self.state = init_state

        for i in range(self.length):
            guessed_feed = (self.feed + self.shift_mod * i) % self.length
            guessed_tap  = (self.tap  + self.shift_mod * i) % self.length

            simulated_states = [self.operation(self.state[(guessed_feed - self.shift_mod * j) % self.length], self.state[(guessed_tap - self.shift_mod * j) % self.length]) & 0xFFFFFFFFFFFFFFFF for j in range(next_state_len)][::-self.shift_mod]

            if simulated_states == next_states:
                # We've found working tap/feed positions. Run the clock difference to synchronize states.
                clock_difference = orig_len - len(outputs)
                self.feed = guessed_feed - self.shift_mod * next_state_len
                self.tap  = guessed_tap  - self.shift_mod * next_state_len

                [self.generate() for _ in range(next_state_len + clock_difference)]
                return

        raise Exception('Unable to find correct tap and feed values.')
