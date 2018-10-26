from samson.utilities.bitstring import Bitstring

class BitslicedGLFSR(object):
    def __init__(self, length, clock_bit, taps, seed=0):
        self.state = bin(seed)[2:].zfill(length)
        self.length = length
        self.clock_bit = clock_bit
        self.taps = taps


    def __repr__(self):
        return f"<BitslicedGLFSR: state={self.state}, length={self.length}, clockbit={self.clock_bit}, taps={self.taps}>"


    def __str__(self):
        return self.__repr__()


    def mix_state(self, in_val, size):
        bit_val = Bitstring.wrap(in_val).zfill(size)

        for bit in str(bit_val)[::-1]:
            self.clock(int(bit))


    def clock(self, bit=0):
        for tap in self.taps:
            position = self.length - tap - 1
            bit ^= int(self.state[position])
        
        self.state += '0'
        self.state = self.state[1:]
        self.state = (self.state[:self.length - 1] + str(bit))


    def value(self):
        return int(self.state[0])

    
    def clock_value(self):
        return int(self.state[self.clock_bit])