from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.des import DES
from samson.block_ciphers.tdes import TDES
from samson.block_ciphers.modes.cbc import CBC
from samson.hashes.md5 import MD5
from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
import re
import base64
import math

RFC1423_ALGOS = {
    "DES-CBC":      (DES, 8),
    "DES-EDE3-CBC": (TDES, 24),
    "AES-128-CBC":  (Rijndael, 16),
    "AES-192-CBC":  (Rijndael, 24),
    "AES-256-CBC":  (Rijndael, 32)
}


def derive_pem_key(passphrase: bytes, salt: bytes, key_size: int) -> Bytes:
    """
    Derives a valid PEM encryption key by mimicking EVP_BytesToKey in OpenSSL.

    Parameters:
        passphrase (bytes): Passphrase.
        salt       (bytes): Salt.
        key_size     (int): Desired key size.
    
    Returns:
        Bytes: Derived key.
    """
    md5 = MD5()
    key = Bytes(b'')

    for _ in range(math.ceil(key_size / 16)):
        key += md5.hash(key + passphrase + salt)

    return key[:key_size]



def create_pem_cbc_obj(passphrase: bytes, algo: str, iv: bytes=None) -> CBC:
    """
    Creates a valid CBC cryptor for PEM.

    Parameters:
        passphrase (bytes): Passphrase to key CBC.
        algo         (str): RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
        iv         (bytes): (Optional) IV to use for CBC encryption.
    
    Returns:
        CBC: Valid CBC cryptor.
    """
    try:
        cipher, key_size = RFC1423_ALGOS[algo]
    except KeyError as _:
        raise ValueError(f'Unsupported cipher "{algo}"')

    if not iv:
        iv = Bytes.random(16)

    key = derive_pem_key(passphrase, iv[:8], key_size)
    cipher_obj = cipher(key=key)
    cbc = CBC(cipher_obj.encrypt, cipher_obj.decrypt, iv[:cipher_obj.block_size], cipher_obj.block_size)
    return cbc



PRE_ENCAPSULATION_BOUNDARY_RE  = re.compile(rb'\s*----(-| )BEGIN (.*)(-| )----')
POST_ENCAPSULATION_BOUNDARY_RE = re.compile(rb'----(-| )END (.*)(-| )----\s*')
HEADER_RE = re.compile(rb'[A-Za-z\-]+: .*')

# https://golang.org/src/crypto/x509/pem_decrypt.go
# https://golang.org/src/crypto/x509/pem_decrypt_test.go
def pem_decode(pem_bytes: bytes, passphrase: bytes=None) -> bytes:
    """
    Decodes PEM bytes into raw bytes.

    Parameters:
        pem_bytes  (bytes): PEM-encoded bytes.
        passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).

    Returns:
        bytes: Decoded bytes.
    """
    pem_bytes = pem_bytes.strip()
    if not PRE_ENCAPSULATION_BOUNDARY_RE.match(pem_bytes):
        raise ValueError('`pem_bytes` must have a valid pre-encapsulation boundary')


    if not POST_ENCAPSULATION_BOUNDARY_RE.search(pem_bytes):
        raise ValueError('`pem_bytes` must have a valid post-encapsulation boundary')


    boundaries_removed = pem_bytes.split(b'\n')[1:-1]

    if boundaries_removed[0] == b'Proc-Type: 4,ENCRYPTED':
        if not passphrase:
            raise ValueError('Encryption header found but passphrase not specified.')


        enc_spec_header = boundaries_removed[1]
        assert enc_spec_header.startswith(b'DEK-Info: ')

        algo, iv = enc_spec_header[10:].split(b',')
        iv = Bytes(iv).unhex()

        cbc = create_pem_cbc_obj(passphrase, algo.decode(), iv)

        headers_removed = base64.b64decode(b''.join(boundaries_removed[2:]).replace(b' ', b''))
        headers_removed = cbc.decrypt(headers_removed)
    else:
        while HEADER_RE.search(boundaries_removed[0]):
            del boundaries_removed[0]

        headers_removed = base64.b64decode(b''.join(boundaries_removed).replace(b' ', b''))


    return headers_removed



def pem_encode(der_bytes: bytes, marker: str, width: int=70, encryption: str=None, passphrase: bytes=None, iv: bytes=None) -> bytes:
    """
    PEM-encodes DER-encoded bytes.

    Parameters:
        der_bytes  (bytes): DER-encoded bytes.
        marker       (str): Header and footer marker (e.g. 'RSA PRIVATE KEY').
        width        (int): Maximum line width before newline.
        encryption   (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
        passphrase (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
        iv         (bytes): (Optional) IV to use for CBC encryption.

    Returns:
        bytes: PEM-encoded bytes.
    """
    additional_headers = ''
    if encryption:
        if not passphrase:
            raise ValueError('Encryption requested found but passphrase not specified.')

        cbc = create_pem_cbc_obj(passphrase, encryption, iv)
        der_bytes = cbc.encrypt(der_bytes)
        additional_headers = f'Proc-Type: 4,ENCRYPTED\nDEK-Info: {encryption},{cbc.iv.hex().upper().decode()}\n\n'

    data = b'\n'.join(get_blocks(base64.b64encode(der_bytes), block_size=width, allow_partials=True))
    return f"-----BEGIN {marker}-----\n{additional_headers}".encode('utf-8') + data + f"\n-----END {marker}-----".encode('utf-8')
