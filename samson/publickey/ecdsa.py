from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes
from samson.publickey.dsa import DSA

# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
class ECDSA(DSA):
    def __init__(self, G, d=None):
        self.G = G
        self.q = self.G.curve.q
        self.d = d or max(1, Bytes.random(self.q.bit_length() + 7 // 8).int() % self.q)
        self.Q = self.d * self.G

    
    def __repr__(self):
        return f"<ECDSA: d={self.d}, G={self.G}, Q={self.Q}>"


    def __str__(self):
        return self.__repr__()
    

    def sign(self, H, message, k=None):
        r = 0
        s = 0

        while s == 0 or r == 0:
            k = k or max(1, Bytes.random(self.q .bit_length() + 7 // 8).int() % self.q)
            inv_k = mod_inv(k, self.q)

            z = H(message)
            z >>= max(z.bit_length() - self.q.bit_length(), 0)

            r = (k * self.G).x % self.q
            s = (inv_k * (z + self.d * r)) % self.q

        return (r, s)
    
    
    def verify(self, H, message, sig):
        (r, s) = sig
        w = mod_inv(s, self.q)

        z = H(message)
        z >>= max(z.bit_length() - self.q.bit_length(), 0)

        u_1 = (z * w) % self.q
        u_2 = (r * w) % self.q
        v = u_1 * self.G + u_2 * self.Q
        return v.x == r

    
    # # Confirmed works on ECDSA as well
    # def derive_k_from_sigs(self, H, msgA, sigA, msgB, sigB):
    #     (rA, sA) = sigA
    #     (rB, sB) = sigB
    #     assert rA == rB
        
    #     s = (sA - sB) % self.q
    #     m = (H(msgA) - H(msgB)) % self.q
    #     return mod_inv(s, self.q) * m % self.q
    
    
    # def derive_x_from_k(self, H, message, k, sig):
    #     (r, s) = sig
    #     self.d = ((s * k) - H(message)) * mod_inv(r, self.q) % self.q