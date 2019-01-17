from types import FunctionType
from copy import deepcopy

class LFG(object):
    """
    Lagged Fibonacci generator
    """

    ADD_OP = lambda a, b: a + b
    SUB_OP = lambda a, b: a - b

    def __init__(self, state: list, tap: int, feed: int, length: int, operation: FunctionType=ADD_OP):
        """
        Parameters:
            state     (list): Initial state.
            tap        (int): Initial tap position.
            feed       (int): Initial feed position.
            length     (int): Length of internal state (modulus).
            operation  (int): The operation the LFG performs. Function that takes in an integer and returns an integer.
        """
        self.state = deepcopy(state)
        self.tap = tap
        self.feed = feed
        self.length = length
        self.operation = operation


    def __repr__(self):
        return f"<LFG: state={self.state}, tap={self.tap}, feed={self.feed}, length={self.length}, operation={self.operation}>"

    def __str__(self):
        return self.__repr__()



    def generate(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        self.tap = (self.tap - 1) % self.length
        self.feed = (self.feed - 1) % self.length

        x = self.operation(self.state[self.feed], self.state[self.tap]) & 0xFFFFFFFFFFFFFFFF
        self.state[self.feed] = x
        return x



    # TODO: This function breaks on some
    # Sometimes when (feed - tap + len(outputs)) % length == 0
    def crack(self, outputs: list):
        """
        Cracks the full state of the LFG.

        Parameters:
            outputs (list): Observed outputs.
        """
        assert len(outputs) > self.length

        # We only need the latest outputs
        outputs = outputs[((len(outputs) // self.length) - 1) * self.length:]

        init_state  = outputs[:self.length][::-1]
        next_states = outputs[self.length:][::-1]

        next_state_len = len(next_states)

        self.state = init_state

        for i in range(self.length):
            guessed_feed = (self.feed - i) % self.length
            guessed_tap = (self.tap - i) % self.length

            simulated_states = [self.operation(self.state[(guessed_feed + j) % self.length], self.state[(guessed_tap + j) % self.length]) & 0xFFFFFFFFFFFFFFFF for j in range(next_state_len)]
            print(guessed_tap, guessed_feed, simulated_states, next_states)

            # if guessed_tap == 43:
            #     print(guessed_feed, simulated_states, next_states)

            if simulated_states == next_states:
                self.feed = guessed_feed + next_state_len
                self.tap = guessed_tap + next_state_len
                [self.generate() for _ in range(next_state_len)]
                return

        raise Exception('Unable to find correct tap and feed values.')
