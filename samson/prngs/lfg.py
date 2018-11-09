class LFG(object):
    ADD_OP = lambda a, b: a + b
    SUB_OP = lambda a, b: a - b

    def __init__(self, state, tap, feed, length, operation=ADD_OP):
        self.state = state
        self.tap = tap
        self.feed = feed
        self.length = length
        self.operation = operation


    def __repr__(self):
        return f"<LFG: state={self.state}, tap={self.tap}, feed={self.feed}, length={self.length}, operation={self.operation}>"

    def __str__(self):
        return self.__repr__()



    def generate(self):
        self.tap = (self.tap - 1) % self.length
        self.feed = (self.feed - 1) % self.length

        x = self.operation(self.state[self.feed], self.state[self.tap]) & 0xFFFFFFFFFFFFFFFF
        self.state[self.feed] = x
        return x