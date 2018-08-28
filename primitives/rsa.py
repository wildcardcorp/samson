from Crypto.Util.number import getPrime
from samson.utilities import *

class RSA(object):
    def __init__(self, bits):
        self.e = 3
        phi = 0

        while gcd(self.e, phi) != 1:
            p, q = getPrime(bits // 2), getPrime(bits // 2)
            phi = lcm(p - 1, q - 1)
            self.n = p * q

        self.d = mod_inv(self.e, phi)

        self.pub = (self.e, self.n)
        self.priv = (self.d, self.n)


    def encrypt(self, message):
        m = int.from_bytes(message, byteorder='big')
        return pow(m, self.e, self.n)


    def decrypt(self, message):
        plaintext = pow(message, self.d, self.n)
        return int_to_bytes(plaintext, 'big')