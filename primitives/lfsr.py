class LFSR(object):
    def __init__(self, init_state):
        self.state = init_state

    # https://en.wikipedia.org/wiki/Linear-feedback_shift_register
    def yield_state(self):
        bit = ((self.state >> 0) ^ (self.state >> 2) ^ (self.state >> 3) ^ (self.state >> 5) ) & 1
        self.state = (self.state >> 1) | (bit << 15)

        return self.state