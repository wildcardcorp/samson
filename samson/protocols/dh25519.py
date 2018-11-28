from samson.utilities.ecc import Curve25519
from samson.utilities.general import rand_bytes

class DH25519(object):
    def __init__(self, key=None, base=None, curve=Curve25519()):
        self.key = curve.clamp_to_curve(key or int.from_bytes(rand_bytes(32), 'big'))
        self.base = base or curve.U


    def __repr__(self):
        return f"<DH25519: key={self.key}, base={self.base}>"


    def __str__(self):
        return self.__repr__()


    def get_challenge(self):
        return self.key * self.base


    def derive_key(self, challenge):
        return self.key * challenge