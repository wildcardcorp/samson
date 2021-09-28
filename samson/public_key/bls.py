from samson.core.primitives import SignatureAlg, Primitive
from samson.utilities.exceptions import NoSolutionException
from samson.math.general import random_int

class BLS(SignatureAlg):
    def __init__(self, curve: 'WeierstrassCurve', G: 'WeierstrassPoint', hash_obj: 'Hash', d: int=None) -> None:
        Primitive.__init__(self)
        self.d        = d or random_int(curve.order())
        self.pub      = G*self.d
        self.curve    = curve
        self.G        = G
        self.hash_obj = hash_obj


    def _map_to_curve(self, msg: bytes) -> 'WeierstrassPoint':
        for i in range(256):
            try:
                msg_ = bytes([i]) + msg
                h    = self.curve(self.hash_obj.hash(msg_).int())

                if (-h).y < h.y:
                    h = -h
                break
            except NoSolutionException:
                pass

        return h


    def sign(self, msg: bytes) -> 'WeierstrassPoint':
        h = self._map_to_curve(msg)
        return self.G.ring(h*self.d)


    def verify(self, msg: bytes, sig) -> bool:
        h  = self._map_to_curve(msg)
        W1 = sig.weil_pairing(self.G, self.curve.order())
        W2 = self.G.ring(h).weil_pairing(self.pub, self.curve.order())
        return W1 == W2
