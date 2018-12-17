from samson.utilities.manipulation import get_blocks
from sympy import Poly, GF
from sympy.abc import x
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import Sequence, Integer, SequenceOf
import math

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



def export_der(items: list, item_types: list=None) -> bytes:
    """
    Converts items (in order) to DER-encoded bytes.

    Parameters:
        items      (list): Items to be encoded.
    
    Returns:
        bytes: DER-encoded sequence bytes.
    """
    seq = Sequence()

    if not item_types:
        item_types = [Integer] * len(items)

    for val, item_type in zip(items, item_types):
        if item_type == SequenceOf:
            item = item_type()
            item.extend(val)
        else:
            item = item_type(val)

        seq.setComponentByPosition(len(seq), item)

    return encoder.encode(seq)



def bytes_to_der_sequence(buffer: bytes, passphrase: bytes=None) -> Sequence:
    """
    Attempts to PEM-decode `buffer` then decodes the result to a DER sequence.

    Parameters:
        buffer     (bytes): The bytes to DER-decode.
        passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
    
    Returns:
        Sequence: DER sequence.
    """
    from samson.utilities.pem import pem_decode
    try:
        buffer = pem_decode(buffer, passphrase)
    except ValueError as e:
        if 'passphrase not specified' in str(e):
            raise e

    seq = decoder.decode(buffer)
    items = seq[0]

    return items



def oid_tuple_to_bytes(oid_tuple: tuple) -> bytes:
    """
    BER-encodes an OID tuple.

    Parameters:
        oid_tuple: OID tuple to encode.
    
    Returns:
        bytes: BER-encoded OID.
    """
    oid_bytes = bytes([oid_tuple[0] * 40 + oid_tuple[1]])

    for next_int in oid_tuple[2:]:
        if next_int < 256:
            oid_bytes += bytes([next_int])
        else:
            as_bin = bin(next_int)[2:]
            as_bin = as_bin.zfill(math.ceil(len(as_bin) / 7) * 7)

            bin_blocks = get_blocks(as_bin, 7)
            new_bin_blocks = ['1' + block for block in bin_blocks[:-1]]
            new_bin_blocks.append('0' + bin_blocks[-1])

            oid_bytes += bytes([int(block, 2) for block in new_bin_blocks])

    return oid_bytes


# TODO: Add decryption support
def parse_openssh(header: bytes, ssh_bytes: bytes) -> list:
    """
    Parses OpenSSH-like formats, including SSH2.

    Parameters:
        header    (bytes): Header that denotes the beginning of sequences (e.g. b'ssh-rsa').
        ssh_bytes (bytes): The bytes to parse.
    
    Returns:
        list: List of parsed Bytes.
    """
    from samson.utilities.bytes import Bytes
    ssh_bytes = ssh_bytes[ssh_bytes.index(header) - 4:]
    ctr = 0
    key_parts = []

    while len(ssh_bytes) - ctr > 4:
        length_spec_end = ctr + 4
        section_length = Bytes(ssh_bytes[ctr:length_spec_end]).int()
        key_parts.append(Bytes(ssh_bytes[length_spec_end:length_spec_end + section_length]))
        ctr += 4 + section_length

    if header in key_parts[-1]:
        private_parts = parse_openssh(header, key_parts[-1])
        key_parts = key_parts[:-1] + private_parts

    return key_parts


def generate_openssh(values: list=[]) -> bytes:
    from samson.utilities.bytes import Bytes

    ssh_encoding = Bytes(b'')
    for item in values:
        if type(item) is int:
            length = (item.bit_length() // 8) + 1
        else:
            length = len(item)

        item = Bytes.wrap(item)
        ssh_encoding += Bytes(length).zfill(4) + item.zfill(length)

    return ssh_encoding



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
