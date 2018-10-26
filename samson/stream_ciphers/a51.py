from samson.prngs.bitsliced_glfsr import BitslicedGLFSR
from sympy import Poly
from sympy.abc import x

# https://github.com/ttsou/airprobe/blob/master/A5.1/python/A51_Tables/a51.py
class A51(object):
    def __init__(self, key, frame_num):
        self.key = key
        self.frame_num = frame_num

        self.lfsr_regs = [
            BitslicedGLFSR(19, 10, [13, 16, 17, 18]),
            BitslicedGLFSR(22, 11, [20, 21]),
            BitslicedGLFSR(23, 12, [7, 20, 21, 22])
        ]

        for lfsr in self.lfsr_regs:
            lfsr.mix_state(self.key, 64)
            lfsr.mix_state(self.frame_num, 22)

        for _ in range(100):
            self.clock()

       
       
    def __repr__(self):
        return f"<A51: key={self.key}, frame_num={self.frame_num}, lfsr_regs={self.lfsr_regs}>"


    def __str__(self):
        return self.__repr__()



    def clock(self):
        majority = sum([lfsr.clock_value() for lfsr in self.lfsr_regs]) // 2

        for lfsr in self.lfsr_regs:
            if lfsr.clock_value() == majority:
                lfsr.clock()


    
    def yield_state(self, size):
        bitstring = ''
        for _ in range(size):
            self.clock()
            bitstring += str(self.lfsr_regs[0].value() ^ self.lfsr_regs[1].value() ^ self.lfsr_regs[2].value())
        
        return int(bitstring, 2)