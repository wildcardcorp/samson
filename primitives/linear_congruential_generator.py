from samson.utilities.math import gcd

class LinearCongruentialGenerator(object):
    def __init__(self, X, a, c, m):
        self.a = a
        self.c = c
        self.m = m

        self.X = X


    def generate(self):
        self.X = (self.a * self.X + self.c) % self.m
        return self.X

    
    def check_full_period(self):
        divisible_by_four = True
        if self.m % 4 == 0:
            divisible_by_four = (self.a - 1) % 4 == 0

        # TODO: Factor 
        return gcd(self.m, self.c) == 1 and divisible_by_four