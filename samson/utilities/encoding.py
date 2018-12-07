from samson.utilities.manipulation import get_blocks
from sympy import Poly, GF
from sympy.abc import x
import base64
import re

# https://en.wikipedia.org/wiki/Non-adjacent_form
def to_NAF(input_arg: bytes) -> list:
    """
    Converts bytes/bytearray or int to Non-adjacent form (NAF).

    Parameters:
        input_arg (bytes): Raw bytes/integer.
    
    Returns:
        list: Sequence in NAF.
    """
    if type(input_arg) is int:
        E = input_arg
    else:
        E = int.from_bytes(input_arg, 'big')
    
    z = []
    
    i = 0
    while E > 0:
        if E % 2 == 1:
            z.append(int(2 - (E % 4)))
            E -= z[-1]
        else:
            z.append(0)
        
        E /= 2
        i += 1
    return z[::-1]


def from_NAF(naf: list) -> int:
    """
    Converts a NAF sequence into an integer.

    Parameters:
        naf (list): NAF sequence.
    
    Returns:
        int: Integer representation.
    """
    total = 0
    reversed_naf = naf[::-1]
    for i in range(len(naf)):
        total += 2 ** i * reversed_naf[i]
    
    return total




def int_to_bytes(n: int, byteorder: str='big') -> bytes:
    """
    Converts an int `n` to bytes.

    Parameters:
        n         (int): Integer.
        byteorder (str): Desired byte order ('big' or 'little').
    
    Returns:
        bytes: Bytes representation of `n`.
    """
    return n.to_bytes(max((n.bit_length() + 7) // 8, 1), byteorder)



def bytes_to_bitstring(input_bytes: bytes, fill: int=8) -> str:
    """
    Converts bytes to a bitstring.

    Parameters:
        input_bytes (bytes): Bytes to convert.
        fill          (int): Length of the output bitstring. Pads with zeroes.
    
    Returns:
        bytes: Bytes representation of `n`.
    """
    return ''.join(format(x, 'b').zfill(fill) for x in input_bytes)


# https://stackoverflow.com/questions/32675679/convert-binary-string-to-bytearray-in-python-3
def bitstring_to_bytes(bitstring: str, byteorder: str='big') -> bytes:
    """
    Converts a bitstring to bytes.

    Parameters:
        bitstring (str): Bitstring to convert.
        byteorder (str): Desired byte order ('big' or 'little').
    
    Returns:
        bytes: Bytes representation.
    """
    return int(bitstring, 2).to_bytes(len(bitstring) // 8, byteorder=byteorder)



PRE_ENCAPSULATION_BOUNDARY_RE  = re.compile(rb'\s*-----BEGIN (.*)-----\n')
POST_ENCAPSULATION_BOUNDARY_RE = re.compile(rb'-----END (.*)-----\s*')

# TODO: Handle encrypted PEM files
def pem_decode(pem_bytes: bytes) -> bytes:
    """
    Decodes PEM bytes into raw bytes.

    Parameters:
        pem_bytes (bytes): PEM-encoded bytes.

    Returns:
        bytes: Decoded bytes.
    """
    if not PRE_ENCAPSULATION_BOUNDARY_RE.match(pem_bytes):
        raise ValueError('`pem_bytes` must have a valid pre-encapsulation boundary')


    if not POST_ENCAPSULATION_BOUNDARY_RE.search(pem_bytes):
        raise ValueError('`pem_bytes` must have a valid post-encapsulation boundary')


    headers_removed = b''.join(pem_bytes.replace(b' ', b'').split()[1:-1])
    return base64.b64decode(headers_removed)



def pem_encode(der_bytes: bytes, marker: str, width: int=70) -> bytes:
    """
    PEM-encodes DER-encoded bytes.

    Parameters:
        der_bytes (bytes): DER-encoded bytes.
        marker      (str): Header and footer marker (e.g. 'RSA PRIVATE KEY').
        width       (int): Maximum line width before newline.

    Returns:
        bytes: PEM-encoded bytes.
    """
    data = b'\n'.join(get_blocks(base64.b64encode(der_bytes), block_size=width, allow_partials=True))
    return f"-----BEGIN {marker}-----\n".encode('utf-8') + data + f"\n-----END {marker}-----".encode('utf-8')



def int_to_poly(integer: int) -> Poly:
    """
    Encodes an integer as a polynomial.

    Parameters:
        integer (int): Integer to encode.
    
    Returns:
        Poly: Polynomial representation.
    """
    return Poly(sum([int(bit) * x ** i for i, bit in enumerate(bin(integer)[2:][::-1])][::-1]) + x, domain=GF(2)) - Poly(x, domain=GF(2))



def poly_to_int(poly: Poly) -> int:
    """
    Encodes an polynomial as a integer.

    Parameters:
        poly (Poly): Polynomial to encode.
    
    Returns:
        int: Integer representation.
    """
    return int(''.join([str(bit) for bit in poly.all_coeffs()]), 2)