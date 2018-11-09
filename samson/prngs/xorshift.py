# https://en.wikipedia.org/wiki/Xorshift
def V32(x):
    x ^= x << 13
    x ^= x >> 17
    x ^= x << 5

    x &= 0xFFFFFFFF

    return x, x


def V64(x):
    x ^= x << 13
    x ^= x >> 7
    x ^= x << 17

    x &= 0xFFFFFFFFFFFFFFFF

    return x, x


def V128(x):
    s = x[3]
    t = x[0]
    t ^= t << 11
    t ^= t >> 8

    x[0] = x[1]
    x[1] = x[2]
    x[2] = x[3]

    t ^= s >> 19
    t ^= s

    return [*x[:-1], t], t



def V116_PLUS(state):
    s1, s0 = state
    state[0] = s0

    s1 ^= (s1 << 24) & 0x3FFFFFFFFFFFFFF
    state[1] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 41)

    return state, (state[1] + s0) & 0x3FFFFFFFFFFFFFF




def V128_PLUS(state):
    s1, s0 = state
    state[0] = s0

    s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
    s1 ^= s1 >> 17
    s1 ^= s0
    s1 ^= s0 >> 26

    state[1] = s1

    return state, sum(state) & 0xFFFFFFFFFFFFFFFF



def V1024_STAR(state):
    p, s = state
    s0 = s[p]

    p = (p + 1) & 15
    s1 = s[p]

    s1 ^= (s1 << 31) & 0xFFFFFFFFFFFFFFFF   
    s[p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30)
    return [p, s], (s[p] * 1181783497276652981) & 0xFFFFFFFFFFFFFFFF



class Xorshift(object):
    def __init__(self, seed, variant=V128_PLUS):
        self.state = seed
        self.variant = variant

    def __repr__(self):
        return f"<Xorshift: state={self.state}, variant={self.variant}>"

    def __str__(self):
        return self.__repr__()
    

    def generate(self):
        self.state, result = self.variant(self.state)
        return result
