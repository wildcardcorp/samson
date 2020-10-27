from samson.core.primitives import Hash
from samson.math.general import random_int_between
from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve, WeierstrassPoint

class ECDHSetIntersectionServer(object):
    """
    References:
        "Protecting accounts from credential stuffing with password breach alerting" https://www.usenix.org/system/files/sec19-thomas.pdf
    """
    def __init__(self, hash_obj: Hash, curve: WeierstrassCurve, trunc: int=1, b: int=None):
        self.hash_obj = hash_obj
        self.curve    = curve
        self.trunc    = trunc
        self.b        = b or random_int_between(2, curve.q)

        self.Q  = (curve.G*self.b).cache_mul(curve.q.bit_length())
        self.db = {}


    def add_element(self, elem: bytes):
        H   = self.hash_obj.hash(elem)
        H_b = self.Q*H.int()
        H_n = H[:self.trunc].int()

        if H_n not in self.db:
            self.db[H_n] = []

        self.db[H_n].append(H_b)


    def create_response(self, H_n: int, H_a: WeierstrassPoint) -> (list, WeierstrassPoint):
        return self.db[H_n], H_a*self.b



class ECDHSetIntersectionClient(object):
    def __init__(self, hash_obj: Hash, curve: WeierstrassCurve, trunc: int=1):
        self.hash_obj = hash_obj
        self.curve    = curve
        self.trunc    = trunc


    def check_element(self, element: bytes, server: ECDHSetIntersectionServer) -> bool:
        H   = self.hash_obj.hash(element)
        H_n = H[:self.trunc].int()

        a   = random_int_between(2, self.curve.q)
        H_a = (self.curve.G*a)*H.int()

        S, H_ab = server.create_response(H_n, H_a)

        return H_ab/a in S
