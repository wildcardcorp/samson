from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes
from samson.publickey.dsa import DSA
from samson.utilities.ecc import EdwardsCurve448, TwistedEdwardsPoint
from samson.hashes.sha3 import SHA3
from copy import deepcopy

def bit(h,i):
  return (h[i//8] >> (i%8)) & 1

# https://ed25519.cr.yp.to/python/ed25519.py
class Ed448(DSA):
    def __init__(self, curve=EdwardsCurve448, hash_obj=SHA3.SHAKE256(912), d=None, A=None):
        self.B = curve.B
        self.curve = curve
        self.d = Bytes.wrap(d or max(1, Bytes.random((curve.b + 7) // 8).int() % curve.q))
        self.H = hash_obj

        self.h = hash_obj.hash(self.d)

        self.a = 2**(curve.b - 9) | sum(2**i * bit(self.h, i) for i in range(2, curve.b-8))
        self.A = A or self.B * self.a



    def __repr__(self):
        return f"<EdDSA: d={self.d}, A={self.A}, curve={self.curve}, H={self.H}>"


    def __str__(self):
        return self.__repr__()
    

    def encode_point(self, P):
        x, y = P.x, P.y
        return Bytes(((x & 1) << self.curve.b-1) + ((y << 1) >> 1), 'little')
    

    def decode_point(self, in_bytes):
        y_bytes = deepcopy(in_bytes)
        y_bytes[-1] &= 0x7F
        y = y_bytes.int()
        x = self.curve.recover_point_from_y(y).x

        if (x & 1) != bit(in_bytes, self.curve.b-1):
            x = self.curve.q - x
        
        return TwistedEdwardsPoint(x, y, self.curve)
        


    def sign(self, message, k=None):
        magic = b"SigEd448" + b'\x00\bx00'
        r = self.H.hash(magic + message)[::-1].int()
        s = self.H.hash(self.h[self.curve.b//8:])[::-1].int()
        # r = self.H.hash(self.h[self.curve.b//8:] + message)[::-1].int()
        R = self.B * (r % self.curve.l)
        k = self.H.hash(magic + self.encode_point(R) + self.encode_point(self.A) + message)[::-1].int()
        S = (r + (k % self.curve.l) * s) % self.curve.l
        # S = (r + self.H.hash(self.encode_point(R) + self.encode_point(self.A) + message)[::-1].int() * self.a) % self.curve.l
        return (self.encode_point(R) + Bytes(S, 'little')).zfill(self.curve.b//4)
    
    

    # def verify(self, message, sig):
    #     sig = Bytes.wrap(sig, 'little')

    #     if len(sig) != self.curve.b // 4:
    #         raise ValueError("`sig` length is wrong.")
        
    #     R = self.decode_point(sig[:self.curve.b//8])
    #     S = sig[self.curve.b//8:].int()
    #     h = self.H.hash(self.encode_point(R) + self.encode_point(self.A) + message)[::-1].int()

    #     return self.B * S == R + (self.A * h)