from sympy.abc import x
from sympy import ZZ, Poly, GF, invert
from sympy.polys.polyerrors import NotInvertible
from samson.utilities.general import shuffle
from samson.utilities.math import is_power_of_two
from samson.utilities.bytes import Bytes
from sympy.ntheory import isprime
import math


def encode_bytes(in_arr: list) -> Bytes:
    """
    Encodes a list of numbers as Bytes.

    Parameters:
        in_arr (list): List to encode.

    Returns:
        Bytes: List encoded as Bytes.
    """
    return Bytes([num % 256 for num in in_arr])



def decode_bytes(in_bytes: bytes) -> list:
    """
    Decodes bytes into a list.

    Parameters:
        in_bytes (bytes): Bytes to decode.
    
    Returns:
        list: List of integer representations of the bytes.
    """
    return [num - 256 if num > 127 else num for num in in_bytes]



def rand_poly(length: int, len_non_zeroes: int, neg_ones_mod: int=0) -> Poly:
    """
    Generates a random polynomial.

    Parameters:
        length         (int): Desired length of polynomial.
        len_non_zeroes (int): Number of non-zero values in polynomial.
        neg_ones_mod   (int): Modifier that reduces the number of -1 coefficients.
    
    Returns:
        Poly: Random polynomial.
    """
    poly_arr =  [0]  * ((length - len_non_zeroes * 2) + neg_ones_mod)
    poly_arr += [1]  * len_non_zeroes
    poly_arr += [-1] * (len_non_zeroes - neg_ones_mod)

    shuffle(poly_arr)

    return Poly(poly_arr, x).set_domain(ZZ)



def invert_poly(f_poly: Poly, R_poly: Poly, p: int) -> Poly:
    """
    Inverts a polynomial `f_poly` over `R_poly` in GF(p).

    Parameters:
        f_poly (Poly): Polynomial to be inverted.
        R_poly (Poly): Polynomial to be inverted _over_.
        p       (int): Integer modulus.
    
    Returns:
        Poly: Inverted polynomial.
    """
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
    """
    Nth-degree TRUncated polynomial ring
    """

    def __init__(self, N: int, p: int=3, q: int=128, f_poly: Poly=None, g_poly: Poly=None):
        """
        Parameters:
            N       (int): Polynomial degree/modulus.
            p       (int): Small modulus.
            q       (int): Large modulus.
            f_poly (Poly): F-polynomial of private key.
            g_poly (Poly): G-polynomial of private key.
        """
        self.N = N
        self.p = p
        self.q = q
        self.R_poly = Poly(x**N - 1, x).set_domain(ZZ)

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
        """
        Generates random private and public keys.
        """
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
        """
        Attempts to find the public key for the current private key. May throw `NotInvertible`.
        """
        self.f_p_poly = invert_poly(self.f_poly, self.R_poly, self.p)
        self.f_q_poly = invert_poly(self.f_poly, self.R_poly, self.q)

        p_f_q_poly = (self.p * self.f_q_poly).trunc(self.q)
        pfq_trunc = (p_f_q_poly * self.g_poly).trunc(self.q)

        self.h_poly = (pfq_trunc % self.R_poly).trunc(self.q)



    def encrypt(self, plaintext: bytes, random_poly: Poly=None) -> Bytes:
        """
        Encrpyts `plaintext`.

        Parameters:
            plaintext  (bytes): Plaintext to encrypt.
            random_poly (Poly): (Optional) The random polynomial used in encryption.

        Returns:
            Bytes: Encrypted ciphertext.
        """
        random_poly = random_poly or rand_poly(self.N, int(math.sqrt(self.q)))

        # Convert plaintext into polynomial
        pt_poly = Poly([int(bit) for bit in bin(int.from_bytes(plaintext, 'big'))[2:].zfill(len(plaintext) * 8)][::-1], x).set_domain(ZZ)
        rhm = (random_poly * self.h_poly).trunc(self.q) + pt_poly
        ct_poly = (rhm % self.R_poly).trunc(self.q)

        return encode_bytes(ct_poly.all_coeffs()[::-1])



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext` into plaintext.

        Parameters:
            ciphertext (bytes): Ciphertext.
        
        Returns:
            Bytes: Decrypted plaintext.
        """
        # Convert ciphertext into polynomial
        ct_poly = decode_bytes(ciphertext)
        msg_poly = Poly(ct_poly[::-1], x).set_domain(ZZ)

        a_poly = ((self.f_poly * msg_poly) % self.R_poly).trunc(self.q)
        b_poly = a_poly.trunc(self.p)

        pt_poly = ((self.f_p_poly * b_poly) % self.R_poly).trunc(self.p)

        bit_length = math.ceil(len(pt_poly.all_coeffs()) / 8) * 8
        pt_bitstring = ''.join([str(bit) for bit in pt_poly.all_coeffs()]).zfill(bit_length)[::-1]
        return Bytes(int(pt_bitstring, 2)).zfill(bit_length // 8)
