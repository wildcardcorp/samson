from samson.utilities.math import gcd, mod_inv
import functools

class LCG(object):
    def __init__(self, X, a, c, m):
        self.a = a
        self.c = c
        self.m = m

        self.X = X


    def __repr__(self):
        return f"<LCG: X={self.X}, a={self.a}, c={self.c}, m={self.m}>"


    def __str__(self):
        return self.__repr__()
        

    def generate(self):
        self.X = (self.a * self.X + self.c) % self.m
        return self.X

    
    def check_full_period(self):
        divisible_by_four = True
        if self.m % 4 == 0:
            divisible_by_four = (self.a - 1) % 4 == 0

        # TODO: Factor 
        return gcd(self.m, self.c) == 1 and divisible_by_four


    # https://tailcall.net/blog/cracking-randomness-lcgs/
    @staticmethod
    def crack(states, multiplier=None, increment=None, modulus=None):
        if not modulus:
            diffs = [state1 - state0 for state0, state1 in zip(states, states[1:])]
            congruences = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
            modulus = abs(functools.reduce(gcd, congruences))

        
        if not multiplier:
            multiplier = (states[2] - states[1]) * mod_inv(states[1] - states[0], modulus) % modulus


        if not increment:
            increment = (states[1] - states[0] * multiplier) % modulus

        return LCG(states[-1], multiplier, increment, modulus)