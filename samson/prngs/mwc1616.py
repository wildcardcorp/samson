class MWC1616(object):
    def __init__(self, seed):
        self.state = seed
    

    def __repr__(self):
        return f"<MWC1616: state={self.state}>"


    def __str__(self):
        return self.__repr__()


    def generate(self):
        s0, s1 = self.state
        s0 = 18030 * (s0 & 0xFFFF) + (s0 >> 16)
        s1 = 30903 * (s1 & 0xFFFF) + (s1 >> 16)

        self.state = [s0, s1]

        return s0 << 16 + (s1 & 0xFFFF)