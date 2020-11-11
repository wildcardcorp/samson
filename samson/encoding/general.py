from samson.utilities.manipulation import get_blocks
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import Sequence as _Sequence, Integer as _Integer, SequenceOf as _SequenceOf
from samson.classical.affine import AffineCipher
from samson.analyzers.analyzer import Analyzer
import urllib.parse
import codecs
import re
import base64
import string
import math


# https://github.com/fwenzel/python-bcrypt
_B64_CHARS = ''.join((string.ascii_uppercase, string.ascii_lowercase, string.digits, '+/')).encode('utf-8')
_B64_CHARS_BCRYPT = ''.join(('./', string.ascii_uppercase, string.ascii_lowercase, string.digits)).encode('utf-8')
_B64_CHARS_URL = ''.join((string.ascii_uppercase, string.ascii_lowercase, string.digits, '-_')).encode('utf-8')

_B64_TO_BCRYPT_TRANSLATION = bytes.maketrans(_B64_CHARS, _B64_CHARS_BCRYPT)
_BCRYPT_TO_B64_TRANSLATION = bytes.maketrans(_B64_CHARS_BCRYPT, _B64_CHARS)
_B64_TO_URL_TRANSLATION = bytes.maketrans(_B64_CHARS, _B64_CHARS_URL)
_URL_TO_B64_TRANSLATION = bytes.maketrans(_B64_CHARS_URL, _B64_CHARS)


def bcrypt_b64_encode(bytestring: bytes) -> bytes:
    """
    Encodes a bytestring with bcrypt's version of base64.

    Parameters:
        bytestring (bytes): Bytes to encode.
    
    Returns:
        bytes: bcrypt-base64 encoded bytestring.
    """
    return base64.b64encode(bytestring).translate(_B64_TO_BCRYPT_TRANSLATION, b'=')


def bcrypt_b64_decode(bytestring: bytes) -> bytes:
    """
    Decodes a bytestring with bcrypt's version of base64.

    Parameters:
        bytestring (bytes): Bytes to decode.
    
    Returns:
        bytes: bcrypt-base64 decoded bytestring.
    """
    # Handle missing padding
    bytestring = bytestring.translate(_BCRYPT_TO_B64_TRANSLATION) + (b'=' * (4 - len(bytestring) % 4))
    return base64.b64decode(bytestring)


def url_b64_encode(bytestring: bytes) -> bytes:
    """
    Encodes a bytestring with URL-safe version of base64.

    Parameters:
        bytestring (bytes): Bytes to encode.
    
    Returns:
        bytes: url-base64 encoded bytestring.
    """
    return base64.b64encode(bytestring).translate(_B64_TO_URL_TRANSLATION, b'=')


def url_b64_decode(bytestring: bytes) -> bytes:
    """
    Decodes a bytestring with a URL-safe version of base64.

    Parameters:
        bytestring (bytes): Bytes to decode.
    
    Returns:
        bytes: url-base64 decoded bytestring.
    """
    # Handle missing padding
    bytestring = bytestring.translate(_URL_TO_B64_TRANSLATION) + (b'=' * (4 - len(bytestring) % 4))
    return base64.b64decode(bytestring)



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

        E //= 2
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
        items (list): Items to be encoded.
    
    Returns:
        bytes: DER-encoded sequence bytes.
    """
    seq = _Sequence()

    if not item_types:
        item_types = [_Integer] * len(items)

    seq_len = 0
    for val, item_type in zip(items, item_types):
        if item_type == _SequenceOf:
            item = item_type()
            item.extend(val)
        else:
            item = item_type(val)

        seq.setComponentByPosition(seq_len, item)
        seq_len += 1

    return encoder.encode(seq)



def bytes_to_der_sequence(buffer: bytes, passphrase: bytes=None) -> _Sequence:
    """
    Attempts to PEM-decode `buffer` then decodes the result to a DER sequence.

    Parameters:
        buffer     (bytes): The bytes to DER-decode.
        passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
    
    Returns:
        Sequence: DER sequence.
    """
    from samson.encoding.pem import pem_decode
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


from enum import Enum
class PKIEncoding(Enum):
    PKCS1     = 0
    PKCS8     = 1
    X509      = 2
    X509_CERT = 3
    OpenSSH   = 4
    SSH2      = 5
    JWK       = 6
    DNS_KEY   = 7
    X509_CSR  = 8



class PKIAutoParser(object):

    @staticmethod
    def get_encoding(buffer: bytes, passphrase: bytes=None):
        from samson.core.encodable_pki import EncodablePKI, ORDER
        from samson.encoding.pem import pem_decode

        subclasses = [EncodablePKI]

        for subclass in subclasses:
            subclasses.extend(subclass.__subclasses__())


        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer, passphrase)

        for encoding in ORDER:
            for subclass in subclasses:
                for encoding_type in [subclass.PRIV_ENCODINGS, subclass.PUB_ENCODINGS]:
                    if encoding in encoding_type:
                        encoder = encoding_type[encoding]

                        if encoder.check(buffer, passphrase=passphrase):
                            return encoder

        raise ValueError("Unable to parse provided key.")


    @staticmethod
    def import_key(buffer: bytes, passphrase: bytes=None):
        from samson.encoding.pem import pem_decode

        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer, passphrase)

        return PKIAutoParser.get_encoding(buffer, passphrase=passphrase).decode(buffer, passphrase=passphrase)


    @staticmethod
    def resolve_x509_signature_alg(name: str):
        from samson.core.encodable_pki import EncodablePKI
        subclasses = [EncodablePKI]

        for subclass in subclasses:
            subclasses.extend(subclass.__subclasses__())

        for subclass in subclasses:
            if hasattr(subclass, 'X509_SIGNING_ALGORITHMS'):
                try:
                    return subclass.X509_SIGNING_ALGORITHMS[name]
                except KeyError:
                    pass



from samson.auxiliary.lazy_loader import LazyLoader
_bytes = LazyLoader('_bytes', globals(), 'samson.utilities.bytes')
class EncodingScheme(Enum):
    PLAIN      = 0
    URL        = 1
    ROT13      = 2
    BASE64     = 3
    BASE64_URL = 4
    BASE32     = 5
    BASE32_HEX = 6
    HEX        = 7
    OCTAL      = 8
    BINARY     = 9


    def encode(self, text: bytes):
        return _bytes.Bytes.wrap(_ENCODERS[self](text))


    def decode(self, text: bytes):
        return _bytes.Bytes.wrap(_DECODERS[self](text))



    @staticmethod
    def get_valid_charsets(text: bytes) -> list:
        candidates = []

        for encoding, regex in _CHARSETS.items():
            char_re = re.compile(regex.encode('utf-8'))

            if char_re.fullmatch(text):
                candidates.append(encoding)

        return candidates


    @staticmethod
    def get_valid_decodings(text: bytes) -> dict:
        candidates = {}

        for encoding in EncodingScheme:
            try:
                decoded = encoding.decode(text)

                if encoding.encode(decoded) == text:
                    candidates[encoding] = decoded
            except:
                pass

        return candidates



    @staticmethod
    def get_best_decoding(text: bytes, analyzer: Analyzer) -> bytes:
        decodings = EncodingScheme.get_valid_decodings(text)
        return analyzer.select_highest_scores(decodings.items(), key=lambda item: item[1])[0]



_CHARSETS = {
    EncodingScheme.PLAIN: r'.*',
    EncodingScheme.HEX: r'(0x)?([a-f0-9]+|[A-F0-9]+)',

    # https://tools.ietf.org/html/rfc4648#section-6
    EncodingScheme.BASE32: r'[A-Z2-7]+(=|={3}|={4}|={6})?',
    EncodingScheme.BASE32_HEX: r'[A-V0-9]+(=|={3}|={4}|={6})?',
    EncodingScheme.BASE64: r'[A-Za-z0-9+/]+={0,2}',
    EncodingScheme.BASE64_URL: r'[A-Za-z0-9-_]+',
    EncodingScheme.ROT13: r'[a-zA-Z]+',
    EncodingScheme.URL: r'[A-Za-z0-9-._~]+',
    EncodingScheme.BINARY: r'(0b)?[0-1]+',
    EncodingScheme.OCTAL: r'(0o)[0-7]+'
}

_rot13_low = AffineCipher(a=1, b=13, alphabet=string.ascii_lowercase)
_rot13_upp = AffineCipher(a=1, b=13, alphabet=string.ascii_uppercase)

_ENCODERS = {
    EncodingScheme.PLAIN: lambda text: text,
    EncodingScheme.HEX: lambda text: codecs.encode(text, 'hex_codec'),
    EncodingScheme.BASE32: base64.b32encode,
    EncodingScheme.BASE64: base64.b64encode,
    EncodingScheme.BASE64_URL: url_b64_encode,
    EncodingScheme.ROT13: lambda text: _rot13_upp.encrypt(_rot13_low.encrypt(text.decode())).encode('utf-8'),
    EncodingScheme.URL: lambda text: urllib.parse.quote_from_bytes(text).encode('utf-8'),
    EncodingScheme.BINARY: lambda text: bin(text).encode('utf-8'),
    EncodingScheme.OCTAL: lambda text: oct(text).encode('utf-8')
}

_DECODERS = {
    EncodingScheme.PLAIN: lambda text: text,
    EncodingScheme.HEX: lambda text: codecs.decode(text, 'hex_codec'),
    EncodingScheme.BASE32: base64.b32decode,
    EncodingScheme.BASE64: base64.b64decode,
    EncodingScheme.BASE64_URL: url_b64_decode,
    EncodingScheme.ROT13: lambda text: _rot13_upp.decrypt(_rot13_low.decrypt(text.decode())).encode('utf-8'),
    EncodingScheme.URL: urllib.parse.unquote_to_bytes,
    EncodingScheme.BINARY: lambda text: int_to_bytes(int(text, 2)),
    EncodingScheme.OCTAL: lambda text: int_to_bytes(int(text, 8))
}
