import hashlib
from samson.utilities.math import modexp
from samson.utilities.general import rand_bytes
from samson.utilities.encoding import int_to_bytes
import codecs

NIST_prime = int.from_bytes(codecs.decode("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 'hex_codec'), 'little')


class SRPServer(object):
    def __init__(self, g=2, k=3, N=NIST_prime):
        self.g = g
        self.k = k
        self.N = N
        self.accounts = {}
        self.requests = {}
        self.salt = rand_bytes(4)

        self.b = int.from_bytes(rand_bytes(4), 'little') % N
        


    def create_account(self, identity, password):
        x = int.from_bytes(hashlib.sha256(self.salt + password).digest(), 'little')
        v = modexp(self.g, x, self.N)
        self.accounts[identity] = v

    
    def respond_with_challenge(self, identity, A):
        v = self.accounts[identity]
        #salt = gen_rand_key(4)
        B = self.k * v + modexp(self.g, self.b, self.N)
        self.requests[identity] = {'A': A, 'B': B} #, 'salt': self.salt
        
        return self.salt, B


    def check_challenge(self, identity, client_hash):
        request = self.requests[identity]
        v = self.accounts[identity]
        A = request['A']

        hex_A = int_to_bytes(A, 'little')
        print(hex_A)
        hex_B = int_to_bytes(request['B'], 'little')

        uH = int.from_bytes(hashlib.sha256(hex_A + hex_B).digest(), 'little')

        p1 = (A * modexp(v, uH, self.N))
        sS = modexp(p1, self.b, self.N)

        sK = hashlib.sha256(int_to_bytes(sS, 'little')).digest()
        return hashlib.sha256(sK + self.salt).digest() == client_hash