import hashlib
from samson.utilities.math import modexp
from samson.utilities.general import rand_bytes
from samson.utilities.encoding import int_to_bytes
import codecs

NIST_prime = int.from_bytes(codecs.decode("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 'hex_codec'), 'little')


class SRPClient(object):
    def __init__(self, identity, password, g=2, k=3, N=NIST_prime):
        self.a = int.from_bytes(rand_bytes(4), 'little') % N
        self.g = g
        self.k = k
        self.A = modexp(g, self.a, N)
        self.identity = identity
        self.password = password
        self.N = N

    
    def make_request(self):
        return self.identity, self.A


    def perform_challenge(self, salt, B):
        hex_A = int_to_bytes(self.A, 'little')
        hex_B = int_to_bytes(B, 'little')

        uH = int.from_bytes(hashlib.sha256(hex_A + hex_B).digest(), 'little')
        xH = int.from_bytes(hashlib.sha256(salt + self.password).digest(), 'little')

        p1 = (B - self.k * modexp(self.g, xH, self.N))
        p2 = (self.a + uH * xH)
        cS = modexp(p1, p2, self.N)

        cK = hashlib.sha256(int_to_bytes(cS, 'little')).digest()
        return hashlib.sha256(cK + salt).digest()


    def craft_malicious_request(self):
        return self.identity, 0


    def craft_auth_bypass(self, salt):
        cK = hashlib.sha256(b'\x00' * 1).digest()
        return hashlib.sha256(cK + salt).digest()