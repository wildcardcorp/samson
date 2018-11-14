from samson.utilities.math import gcd, lcm, mod_inv, find_prime
from samson.utilities.encoding import int_to_bytes, pem_encode, pem_decode
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import Sequence, Integer
import random

class RSA(object):
    def __init__(self, bits, p=None, q=None, e=None):
        if p and q and not e:
            raise Exception("Argument 'e' must be set if 'p' and 'q' are set. ")

        self.e = e or 3
        phi = 0

        if p and q:
            phi = lcm(p - 1, q - 1)
            self.n = p * q

            if gcd(self.e, phi) != 1:
                raise Exception("Invalid 'p' and 'q': GCD(e, phi) != 1")
        else:
            while gcd(self.e, phi) != 1:
                p, q = find_prime(bits // 2), find_prime(bits // 2)
                phi = lcm(p - 1, q - 1)
                self.n = p * q

        self.p = p
        self.q = q

        self.bits = bits

        self.phi = phi
        self.d = mod_inv(self.e, phi)
        self.alt_d = mod_inv(self.e, (self.p - 1) * (self.q - 1))

        self.pub = (self.e, self.n)
        self.priv = (self.d, self.n)



    def __repr__(self):
        return f"<RSA: bits={self.bits}, p={self.p}, q={self.q}, e={self.e}, n={self.n}, phi={self.phi}, d={self.d}, alt_d={self.alt_d}>"



    def __str__(self):
        return self.__repr__()

        
    def encrypt(self, message):
        m = int.from_bytes(message, byteorder='big')
        return pow(m, self.e, self.n)


    def decrypt(self, message):
        plaintext = pow(message, self.d, self.n)
        return int_to_bytes(plaintext, 'big')



    def export_key(self, encode_pem=True):
        seq = Sequence()

        for x in [0, self.n, self.e, self.d, self.p, self.q]:
            seq.setComponentByPosition(len(seq), Integer(x))
        
        der_encoded = encoder.encode(seq)

        if pem_encode:
            der_encoded = pem_encode(der_encoded, 'RSA PRIVATE KEY')

        return der_encoded

    
    @staticmethod
    def import_key(buffer):
        try:
            buffer = pem_decode(buffer)
        except ValueError as _:
            pass
        

        seq = decoder.decode(buffer)
        _n, e, _d, p, q = [int(item) for item in seq[0][1:]]
        rsa = RSA(0, p=p, q=q, e=e)
        rsa.bits = rsa.n.bit_length()
        return rsa
    



    @staticmethod
    def factorize_from_shared_p(n1, n2, e):
        assert n1 != n2

        # Find shared `p`
        p = gcd(n1, n2)

        q1 = n1 // p
        q2 = n2 // p

        return (RSA(0, p=p, q=q1, e=e), RSA(0, p=p, q=q2, e=e))


    @staticmethod
    def factorize_from_faulty_crt(message, faulty_sig, e, n):
        q = gcd(pow(faulty_sig, e, n) - message, n)
        p = n // q

        return RSA(0, p=p, q=q, e=e)


    @staticmethod
    def factorize_from_d(d, e, n):
        k = d*e - 1
        p = None
        q = None

        while not p:
            g = random.randint(2, n - 1)
            t = k
            while t % 2 == 0:
                t = t // 2
                x = pow(g, t, n)
                if x > 1 and gcd(x - 1, n) > 1:
                    p = gcd(x - 1, n)
                    q = n // p
                    break
            
        return RSA(0, p=p, q=q, e=e)