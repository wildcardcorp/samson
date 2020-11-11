from samson.math.polynomial import Polynomial
from samson.math.symbols import Symbol
from samson.math.algebra.rings.integer_ring import ZZ
from samson.utilities.exceptions import NotInvertibleException

from samson.utilities.general import shuffle
from samson.math.general import is_power_of_two, is_prime, mod_inv
from samson.utilities.bytes import Bytes
from samson.core.primitives import NumberTheoreticalAlg, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec, SecurityProofType, FrequencyType
from samson.ace.decorators import register_primitive
import math

x = Symbol('x')
P = ZZ[x]

def all_coeffs(poly: Polynomial) -> list:
    """
    Returns the coefficients of a `poly` as a dense integer vector.

    Parameters:
        poly (Polynomial): Polynomial.
    
    Returns:
        list: Integer vector.
    """
    return [int(poly.coeffs[i]) for i in range(poly.coeffs.last() + 1)]


def minimize_poly(poly: Polynomial, mod: int) -> list:
    """
    Minimizes the absolute distance between coefficients and zero in a symmetric ring.

    Parameters:
        poly (Polynomial): Polynomial.
        mod         (int): Modulus.
    
    Returns:
        list: Coefficient list.
    """
    return [coeff - mod if abs(coeff - mod) < coeff else coeff for coeff in all_coeffs(poly)]


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



def rand_poly(length: int, len_non_zeroes: int, neg_ones_mod: int=0) -> Polynomial:
    """
    Generates a random polynomial.

    Parameters:
        length         (int): Desired length of polynomial.
        len_non_zeroes (int): Number of non-zero values in polynomial.
        neg_ones_mod   (int): Modifier that reduces the number of -1 coefficients.
    
    Returns:
        Polynomial: Random polynomial.
    """
    poly_arr  = [0]  * ((length - len_non_zeroes * 2) + neg_ones_mod)
    poly_arr += [1]  * len_non_zeroes
    poly_arr += [-1] * (len_non_zeroes - neg_ones_mod)

    shuffle(poly_arr)

    return Polynomial(poly_arr, ZZ)



def invert_poly(f_poly: Polynomial, R_poly: Polynomial, p: int) -> Polynomial:
    """
    Inverts a polynomial `f_poly` over `R_poly` in GF(p).

    Parameters:
        f_poly (Polynomial): Polynomial to be inverted.
        R_poly (Polynomial): Polynomial to be inverted _over_.
        p             (int): Integer modulus.

    Returns:
        Polynomial: Inverted polynomial.
    """
    power_of_two = is_power_of_two(p)
    if is_prime(p) or power_of_two:
        if power_of_two:
            Z_p = ZZ/ZZ(2)
        else:
            Z_p = ZZ/ZZ(p)

        f_poly_p = Polynomial([(idx, Z_p[coeff]) for idx, coeff in f_poly.coeffs], Z_p)
        R_poly_p = Polynomial([(idx, Z_p[coeff]) for idx, coeff in R_poly.coeffs], Z_p)

        inv_poly = mod_inv(f_poly_p, R_poly_p)
        inv_poly = Polynomial([(idx, ZZ[int(coeff)]) for idx, coeff in inv_poly.coeffs], ZZ)

        if power_of_two:
            for _ in range(int(math.log(p, 2))):
                inv_poly = (2 * inv_poly) - (f_poly * (inv_poly ** 2))
                inv_poly = (inv_poly % R_poly).trunc(p)

    else:
        raise NotInvertibleException(f"Polynomial not invertible in Z_{p}. NTRU: p and q must be prime or power of two.")

    return inv_poly



# https://en.wikipedia.org/wiki/NTRUEncrypt
@register_primitive()
class NTRU(NumberTheoreticalAlg):
    """
    Nth-degree TRUncated polynomial ring
    """

    SECURITY_PROOF  = SecurityProofType.SHORTEST_VECTOR
    KEY_SIZE        = SizeSpec(size_type=SizeType.ARBITRARY, typical=[167, 251, 347, 503])
    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.KEY, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda ntru: ntru.N))
    USAGE_FREQUENCY = FrequencyType.UNUSUAL

    def __init__(self, N: int, p: int=3, q: int=128, f_poly: Polynomial=None, g_poly: Polynomial=None):
        """
        Parameters:
            N             (int): Polynomial degree/modulus.
            p             (int): Small modulus.
            q             (int): Large modulus.
            f_poly (Polynomial): F-polynomial of private key.
            g_poly (Polynomial): G-polynomial of private key.
        """
        Primitive.__init__(self)
        self.N = N
        self.p = p
        self.q = q
        self.R_poly = x**N - 1

        self.f_poly = f_poly
        self.g_poly = g_poly
        self.h_poly = None

        priv_not_specified = [poly is None for poly in [f_poly, g_poly]]

        # Generate random keys
        if all(priv_not_specified):
            self.generate_random_keys()

        # Tried to specify only part of private key
        elif any(priv_not_specified):
            raise ValueError("Must provide ALL values for private key: f_poly, g_poly")

        # Specified private key, but not public key
        else:
            self.generate_public_key()



    # def __repr__(self):
    #     return f"<NTRU: N={self.N}, p={self.p}, q={self.q}, f_poly={self.f_poly}, g_poly={self.g_poly}, h_poly={self.h_poly}>"

    # def __str__(self):
    #     return self.__repr__()




    def generate_random_keys(self):
        """
        Generates random private and public keys.
        """
        self.g_poly = rand_poly(self.N, int(math.sqrt(self.q)))

        while True:
            try:
                self.f_poly = rand_poly(self.N, self.N // 3, neg_ones_mod=1)
                self.generate_public_key()

                break
            except NotInvertibleException as _:
                pass



    def generate_public_key(self):
        """
        Attempts to find the public key for the current private key. May throw `NotInvertibleException`.
        """
        self.f_p_poly = invert_poly(self.f_poly, self.R_poly, self.p)
        self.f_q_poly = invert_poly(self.f_poly, self.R_poly, self.q)

        p_f_q_poly  = (self.p * self.f_q_poly).trunc(self.q)
        pfq_trunc   = (p_f_q_poly * self.g_poly).trunc(self.q)
        self.h_poly = (pfq_trunc % self.R_poly).trunc(self.q)


    def encrypt(self, plaintext: bytes, random_poly: Polynomial=None) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext        (bytes): Plaintext to encrypt.
            random_poly (Polynomial): (Optional) The random polynomial used in encryption.

        Returns:
            Bytes: Encrypted ciphertext.
        """
        random_poly = random_poly or rand_poly(self.N, int(math.sqrt(self.q)))

        # Convert plaintext into polynomial
        pt_poly = P([int(bit) for bit in bin(int.from_bytes(plaintext, 'big'))[2:].zfill(len(plaintext) * 8)])
        rhm     = (random_poly * self.h_poly).trunc(self.q) + pt_poly
        ct_poly = (rhm % self.R_poly).trunc(self.q)

        return encode_bytes(minimize_poly(ct_poly, self.q))



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext` into plaintext.

        Parameters:
            ciphertext (bytes): Ciphertext.
        
        Returns:
            Bytes: Decrypted plaintext.
        """
        # Convert ciphertext into polynomial
        ct_poly  = decode_bytes(ciphertext)
        msg_poly = P(ct_poly)

        a_poly = ((self.f_poly * msg_poly) % self.R_poly).trunc(self.q)
        a_poly = P(minimize_poly(a_poly, self.q))
        b_poly = a_poly.trunc(self.p)

        pt_poly = ((self.f_p_poly * b_poly) % self.R_poly).trunc(self.p)

        bit_length   = math.ceil(pt_poly.coeffs.len() / 8) * 8
        pt_bitstring = ''.join([str(bit % 2) for bit in all_coeffs(pt_poly)])[::-1].zfill(bit_length)[::-1]
        return Bytes(int(pt_bitstring, 2)).zfill(bit_length // 8)
