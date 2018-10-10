from samson.utilities.bytes import Bytes
from samson.utilities.math import mod_inv
from samson.hashes.md5 import MD5
from samson.protocols.diffie_hellman import DiffieHellman

# https://asecuritysite.com/encryption/dragonfly
class Dragonfly(object):
    def __init__(self, key, H=lambda m: MD5().hash(m), q=DiffieHellman.MODP_2048):
        self.key = key
        self.q = q
        self.A = Bytes.random(16).to_int()
        self.a = Bytes.random(16).to_int()
        self.H = H

    
    def __repr__(self):
        return f"<Dragonfly: key={self.key}, H={self.H}, A={self.A}, a={self.a}, q={self.q}>"


    def __str__(self):
        return self.__repr__()


    def get_challenge(self):
        sA = self.a + self.A

        PE = int.from_bytes(self.H(self.key)[:8], 'big')
        eA = mod_inv(pow(PE, self.A, self.q), self.q)
        return pow(PE, sA, self.q), eA


    def derive_key(self, challenge):
        PEsA, eA = challenge
        return pow(PEsA * eA, self.a, self.q)