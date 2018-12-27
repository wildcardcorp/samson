from samson.encoding.openssh.literal import Literal
from samson.encoding.openssh.kdf_params import KDFParams
from samson.encoding.openssh.openssh_private_header import OpenSSHPrivateHeader
from samson.encoding.pem import pem_encode
from samson.utilities.bytes import Bytes
import base64
from types import FunctionType


def check_decrypt(params: bytes, decryptor: FunctionType) -> (bytes, bytes):
    """
    Performs an optional decryption and checks the "check bytes" to ensure the key is valid.

    Parameters:
        params   (bytes): Current encoded parameter buffer.
        decryptor (func): Function to decrypt the private key.
    
    Returns:
        (bytes, bytes): Formatted as (check bytes, left over bytes).
    """
    if decryptor:
        params = decryptor(params)

    check_bytes, params = Literal('check_bytes', length=8).unpack(params)
    check1, check2 = check_bytes.chunk(4)

    if check1 != check2:
        raise ValueError(f'Private key check bytes incorrect. Is it encrypted? check1: {check1}, check2: {check2}')

    return check_bytes, params



def generate_openssh_private_key(public_key: object, private_key: object, encode_pem: bool, marker: str, encryption: str, iv: bytes, passphrase: bytes) -> bytes:
    """
    Internal function. Generates OpenSSH private keys for various PKI.

    Parameters:
        public_key  (object): OpenSSH public key object.
        private_key (object): OpenSSH private key object.
        encode_pem    (bool): Whether or not to PEM encode.
        marker         (str): PEM markers.
        encryption     (str): Encryption algorithm to use.
        iv           (bytes): IV for encryption algorithm.
        passphrase   (bytes): Passphrase for KDF.
    
    Returns:
        bytes: OpenSSH encoded PKI object.
    """
    if encryption:
        kdf_params = KDFParams('kdf_params', iv or Bytes.random(16), 16)
    else:
        kdf_params = KDFParams('kdf_params', b'', b'')

    if encryption and type(encryption) is str:
        encryption = encryption.encode('utf-8')

    header = OpenSSHPrivateHeader(
        header=OpenSSHPrivateHeader.MAGIC_HEADER,
        encryption=encryption or b'none',
        kdf=b'bcrypt' if encryption else b'none',
        kdf_params=kdf_params,
        num_keys=1
    )

    encryptor, padding_size = None, 8
    if passphrase:
        encryptor, padding_size = header.generate_encryptor(passphrase)

    packed_key = header.pack() + public_key.pack(public_key) + private_key.pack(private_key, encryptor, padding_size)
    if encode_pem:
        encoded = pem_encode(packed_key, marker or 'OPENSSH PRIVATE KEY')

    return encoded



def generate_openssh_public_key_params(encoding: str, ssh_header: bytes, public_key: object) -> (bytes, bool, str, bool):
    """
    Internal function. Generates OpenSSH public key parameters for various PKI.

    Parameters:
        encoding      (str): Encoding to use. Currently supports 'OpenSSH' and 'SSH2'.
        ssh_header  (bytes): PKI-specific SSH header.
        public_key (object): OpenSSH public key object.
    
    Returns:
        (bytes, bool, str, bool): PKI public key parameters formatted as (encoded, default_pem, default_marker, use_rfc_4716).
    """
    use_rfc_4716 = False
    default_marker = None

    if encoding.upper() == 'OpenSSH'.upper():
        encoded = ssh_header + b' ' + base64.b64encode(public_key.pack(public_key)[4:]) + b' nohost@localhost'
        default_pem = False

    elif encoding.upper() == 'SSH2'.upper():
        encoded = public_key.pack(public_key)[4:]
        default_marker = 'SSH2 PUBLIC KEY'
        default_pem = True
        use_rfc_4716 = True

    else:
        raise ValueError(f'Unsupported encoding "{encoding}"')

    return encoded, default_pem, default_marker, use_rfc_4716



def parse_openssh_key(buffer: bytes, ssh_header: bytes, public_key_cls: object, private_key_cls: object, passphrase: bytes) -> (object, object):
    """
    Internal function. Parses various PKI keys.

    Parameters:
        buffer           (bytes): Byte-encoded OpenSSH key.
        ssh_header       (bytes): PKI-specific SSH header.
        public_key_cls  (object): OpenSSH public key class.
        private_key_cls (object): OpenSSH private key class.
        passphrase       (bytes): Passphrase for KDF.
    
    Returns:
        (object, object): Parsed private and public key objects formatted as (private key, public key).
    """
    priv = None

    # SSH private key?
    if OpenSSHPrivateHeader.MAGIC_HEADER in buffer:
        header, left_over = OpenSSHPrivateHeader.unpack(buffer)
        pub, left_over = public_key_cls.unpack(left_over)

        decryptor = None
        if passphrase:
            decryptor = header.generate_decryptor(passphrase)

        priv, _left_over = private_key_cls.unpack(left_over, decryptor)
    else:
        if buffer.split(b' ')[0][:len(ssh_header)] == ssh_header:
            buffer = base64.b64decode(buffer.split(b' ')[1])

        pub, _ = public_key_cls.unpack(buffer, already_unpacked=True)

    return priv, pub
