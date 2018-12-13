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
