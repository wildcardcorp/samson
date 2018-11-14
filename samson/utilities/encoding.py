from samson.utilities.manipulation import get_blocks
import base64
import re

# https://en.wikipedia.org/wiki/Non-adjacent_form
# Takes in bytes/bytearray or int
def to_NAF(input_arg):
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


def from_NAF(naf):
    total = 0
    reversed_naf = naf[::-1]
    for i in range(len(naf)):
        total += 2 ** i * reversed_naf[i]
    
    return total




def int_to_bytes(n, byteorder='big'):
    """Converts the given int n to bytes and returns them."""
    return n.to_bytes(max((n.bit_length() + 7) // 8, 1), byteorder)



def bytes_to_bitstring(input_bytes, fill=8):
    return ''.join(format(x, 'b').zfill(fill) for x in input_bytes)


# https://stackoverflow.com/questions/32675679/convert-binary-string-to-bytearray-in-python-3
def bitstring_to_bytes(bistring, byteorder='big'):
    return int(bistring, 2).to_bytes(len(bistring) // 8, byteorder=byteorder)



PRE_ENCAPSULATION_BOUNDARY_RE  = re.compile(rb'\s*-----BEGIN (.*)-----\n')
POST_ENCAPSULATION_BOUNDARY_RE = re.compile(rb'-----END (.*)-----\s*')

# TODO: Handle encrypted PEM files
def pem_decode(pem_bytes):
    if not PRE_ENCAPSULATION_BOUNDARY_RE.match(pem_bytes):
        raise ValueError('`pem_bytes` must have a valid pre-encapsulation boundary')


    if not POST_ENCAPSULATION_BOUNDARY_RE.search(pem_bytes):
        raise ValueError('`pem_bytes` must have a valid post-encapsulation boundary')


    headers_removed = b''.join(pem_bytes.replace(b' ', b'').split()[1:-1])
    return base64.b64decode(headers_removed)



def pem_encode(der_bytes, marker, width=70):
    data = b'\n'.join(get_blocks(base64.b64encode(der_bytes), block_size=width, allow_partials=True))
    return f"-----BEGIN {marker}-----\n".encode('utf-8') + data + f"\n-----END {marker}-----".encode('utf-8')