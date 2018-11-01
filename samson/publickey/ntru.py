from sympy.abc import x
from sympy import ZZ, Poly, GF, invert
from sympy.polys.polyerrors import NotInvertible
from samson.utilities.general import shuffle
from samson.utilities.math import is_power_of_two
from samson.utilities.encoding import int_to_bytes
from sympy.ntheory import isprime
import math


def encode_bytes(in_arr):
    return bytes([num % 256 for num in in_arr])


def decode_bytes(in_arr):
    return [num - 256 if num > 127 else num for num in in_arr]


def rand_poly(length, len_non_zeroes, neg_ones_mod=0):
    poly_arr =  [0]  * ((length - len_non_zeroes * 2) + neg_ones_mod)
    poly_arr += [1]  * len_non_zeroes
    poly_arr += [-1] * (len_non_zeroes - neg_ones_mod)

    shuffle(poly_arr)

    return Poly(poly_arr, x).set_domain(ZZ)





def invert_poly(f_poly, R_poly, p):
    if isprime(p):
        inv_poly = invert(f_poly, R_poly, domain=GF(p))

    elif is_power_of_two(p):
        inv_poly = invert(f_poly, R_poly, domain=GF(2))

        for _ in range(int(math.log(p, 2))):
            inv_poly = (2 * inv_poly) - (f_poly * (inv_poly ** 2))
            inv_poly = (inv_poly % R_poly).trunc(p)
    else:
        raise Exception(f"Polynomial not invertible in Z_{p}. NTRU: p and q must be prime or power of two.")
    
    return inv_poly



# https://en.wikipedia.org/wiki/NTRUEncrypt
class NTRU(object):
    def __init__(self, N, p, q, f_poly=None, g_poly=None):
        self.N = N
        self.p = p
        self.q = q
        self.R_poly = Poly(x ** N - 1, x).set_domain(ZZ)

        self.f_poly = f_poly
        self.g_poly = g_poly
        self.h_poly = None

        priv_not_specified = [poly is None for poly in [f_poly, g_poly]]

        # Generate random keys
        if all(priv_not_specified):
            self.generate_random_keys()

        # Tried to specify only part of private key
        elif any(priv_not_specified):
            raise Exception("Must provide ALL values for private key: f_poly, g_poly")

        # Specified private key, but not public key
        else:
            self.generate_public_key()


    def __repr__(self):
        return f"<NTRU: N={self.N}, p={self.p}, q={self.q}, f_poly={self.f_poly}, g_poly={self.g_poly}, h_poly={self.h_poly}>"
    

    def __str__(self):
        return self.__repr__()


    
    def generate_random_keys(self):
        self.g_poly = rand_poly(self.N, int(math.sqrt(self.q)))

        inversion_successful = False
        while not inversion_successful:
            try:
                self.f_poly = rand_poly(self.N, self.N // 3, neg_ones_mod=1)

                self.generate_public_key()
                inversion_successful = True
            except NotInvertible as _:
                pass
    


    def generate_public_key(self):
        self.f_p_poly = invert_poly(self.f_poly, self.R_poly, self.p)
        self.f_q_poly = invert_poly(self.f_poly, self.R_poly, self.q)

        p_f_q_poly = (self.p * self.f_q_poly).trunc(self.q)
        pfq_trunc = (p_f_q_poly * self.g_poly).trunc(self.q)

        self.h_poly = (pfq_trunc % self.R_poly).trunc(self.q)



    def encrypt(self, plaintext, random_poly=None):
        random_poly = random_poly or rand_poly(self.N, int(math.sqrt(self.q)))

        # Convert plaintext into polynomial
        pt_poly = Poly([int(bit) for bit in bin(int.from_bytes(plaintext, 'big'))[2:]][::-1], x).set_domain(ZZ)

        rhm = (random_poly * self.h_poly).trunc(self.q) + pt_poly
        ct_poly = (rhm % self.R_poly).trunc(self.q)

        return encode_bytes(ct_poly.all_coeffs()[::-1])
    


    def decrypt(self, ciphertext):
        # Convert ciphertext into polynomial
        ct_poly = decode_bytes(ciphertext)
        msg_poly = Poly(ct_poly[::-1], x).set_domain(ZZ)

        a_poly = ((self.f_poly * msg_poly) % self.R_poly).trunc(self.q)
        b_poly = a_poly.trunc(self.p)

        pt_poly = ((self.f_p_poly * b_poly) % self.R_poly).trunc(self.p)

        pt_bitstring = ''.join([str(bit) for bit in pt_poly.all_coeffs()[::-1]])
        return int_to_bytes(int(pt_bitstring, 2))
