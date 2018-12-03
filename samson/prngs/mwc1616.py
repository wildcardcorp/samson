# https://github.com/XMPPwocky/nodebeefcl/blob/master/beef.py
# https://github.com/v8/v8/blob/ceade6cf239e0773213d53d55c36b19231c820b5/src/js/math.js#L143
# https://v8.dev/blog/math-random <-- Looks to be wrong
# http://www.helsbreth.org/random/rng_mwc1616.html
class MWC1616(object):
    def __init__(self, seed, a=18030, b=30903, bits=32):
        if type(seed) == int:
            seed = ((seed >> 16) & 0xFFFF, seed & 0xFFFF)

        self.state = seed
        self.a = a
        self.b = b
        self.bits = bits
        self._mask = 2**bits - 1
    

    def __repr__(self):
        return f"<MWC1616: state={self.state}, a={self.a}, b={self.b}, bits={self.bits}>"


    def __str__(self):
        return self.__repr__()


    def generate(self):
        s0, s1 = self.state
        s0 = (self.a * (s0 & 0xFFFF) + (s0 >> 16)) & self._mask
        s1 = (self.b * (s1 & 0xFFFF) + (s1 >> 16)) & self._mask

        self.state = [s0, s1]

        return ((s0 << 16) + (s1 & 0xFFFF)) & self._mask