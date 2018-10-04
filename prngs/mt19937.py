#!/usr/bin/python3
w, n, m, r = (32, 624, 397, 31)
a = 0x9908b0df
f = 1812433253
u, d = (11, 0xFFFFFFFF)
s, b = (7, 0x9D2C5680)
t, c = (15, 0xEFC60000)
l = 18


def asint32(integer):
    return integer & d

def temper(y):
    y ^= (y >> u)
    y ^= (y << s) & b
    y ^= (y << t) & c
    y ^= (y >> l)
    return y


# Implementation of MT19937
class MT19937:

    def __init__(self, seed=0):
        self.state = [0] * n
        self.seed = seed

        # Seed the algo
        self.index = n
        self.state[0] = seed

        for i in range(1, n):
            self.state[i] = asint32(f * (self.state[i - 1] ^ self.state[i - 1] >> (w - 2)) + i)


    def __repr__(self):
        return "<MT19937: seed={}, index={}, state={}>".format(self.seed, self.index, self.state)


    def __str__(self):
        return self.__repr__()
        

    def twist(self):
        for i in range(n):
            y = asint32((self.state[i] & 0x80000000) + (self.state[(i + 1) % n] & 0x7fffffff))
            self.state[i] = self.state[(i + m) % n] ^ y >> 1

            if y & 1 == 1:
                self.state[i] ^= a

        self.index = 0


    def randint(self):
        if self.index >= n:
            self.twist()

        y = self.state[self.index]
        y  = temper(y)

        self.index += 1

        return asint32(y)


if __name__ == '__main__':
    random = MT19937(0)
    assert random.randint() == 2357136044
    for i in range(1000): random.randint()
    assert random.randint() == 1193028842
