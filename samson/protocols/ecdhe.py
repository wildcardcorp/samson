from fastecdsa.point import Point
from fastecdsa.curve import P256
from samson.utilities.general import rand_bytes

class ECDHE(object):
    def __init__(self, key=None, G=P256.G):
        self.key = key or int.from_bytes(rand_bytes(), 'big')
        self.G = G


    def __repr__(self):
        return f"<ECDHE: key={self.key}, G={self.G}>"


    def __str__(self):
        return self.__repr__()


    def get_challenge(self):
        return self.key * self.G


    def derive_key(self, challenge):
        return self.key * challenge