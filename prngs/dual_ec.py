from samson.utilities.bytes import Bytes
from samson.utilities.math import tonelli, mod_inv
from fastecdsa.point import Point
import random

class DualEC(object):
    # P and Q are Point objects from fastecdsa
    def __init__(self, P, Q, seed):
        self.P = P
        self.Q = Q
        self.t = seed
        self.r = None


    def __repr__(self):
        return f"<DualEC: P={self.P}, Q={self.Q}, t={self.t}>"


    def __str__(self):
        return self.__repr__()


    def generate(self):
        s = (self.t * self.P).x
        self.t = s
        self.r = (s * self.Q).x

        return Bytes(int.to_bytes(self.r, 32, 'big')[2:])


    @staticmethod
    def generate_backdoor(curve):
        P = curve.G
        d = random.randint(2, curve.q)
        e = mod_inv(d, curve.q)
        Q = e * P

        return P, Q, d


    @staticmethod
    def derive_from_backdoor(P, Q, d, observed_out):
        assert len(observed_out) >= 30

        curve = P.curve

        r1 = observed_out[:30]
        r2 = observed_out[30:]

        possible_states = []

        for i in range(2**16):
            test_r1 = int.to_bytes(i, 2, 'big') + r1
            test_x = int.from_bytes(test_r1, 'big')
            try:
                y_2 = test_x ** 3 + (curve.a * test_x) + curve.b
                y = tonelli(y_2, curve.p)
                R = Point(test_x, y)
                dR = d * R
                test_r2 = dR.x * Q

                if int.to_bytes(test_r2.x, 32, 'big')[2:2 + len(r2)] == r2:
                    possible_states.append(DualEC(P, Q, dR.x))
                    print(test_r2)
            except Exception as _:
                pass

        return possible_states