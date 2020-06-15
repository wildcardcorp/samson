from samson.encoding.openssh.core.packed_bytes import PackedBytes
from samson.utilities.bytes import Bytes
from samson.encoding.openssh.general import check_decrypt
from samson.encoding.openssh.core.literal import Literal
from samson.padding.incremental_padding import IncrementalPadding
from types import FunctionType

class ECDSAPrivateKey(object):
    """
    OpenSSH encoding for an ECDSA private key.
    """

    def __init__(self, name: str, check_bytes: bytes=None, curve: bytes=None, x_y_bytes: bytes=None, d: int=None, host: bytes=None):
        """
        Parameters:
            name          (str): Name for bookkeeping purposes.
            check_bytes (bytes): Four random bytes repeated for OpenSSH to check if the decryption worked.
            curve       (bytes): Elliptical curve name.
            x_y_bytes   (bytes): Byte encoding of x and y.
            host        (bytes): Host the key was generated on.
        """
        self.name = name
        self.check_bytes = check_bytes or Bytes.random(4) * 2
        self.curve = curve
        self.x_y_bytes = x_y_bytes
        self.d = d
        self.host = host


    def __repr__(self):
        return f"<ECDSAPrivateKey: name={self.name}, curve={self.curve}, x_y_bytes={self.x_y_bytes}, d={self.d}, host={self.host}>"

    def __str__(self):
        return self.__repr__()



    @staticmethod
    def pack(value: 'ECDSAPrivateKey', encryptor: FunctionType=None, padding_size: int=8) -> Bytes:
        """
        Packs a private key into an OpenSSH-compliant encoding.

        Parameters:
            value (ECDSAPrivateKey): Value to encode.
            encryptor        (func): (Optional) Function to use as the encryptor.
            padding_size      (int): The block size to pad to. Usually 8 unless you're encrypting.
        
        Returns:
            Bytes: Packed bytes.
        """
        check_bytes = Literal('check_bytes', length=8).pack(value.check_bytes)
        encoded = check_bytes + PackedBytes('ecdsa-header').pack(b'ecdsa-sha2-' + value.curve) + PackedBytes('curve').pack(value.curve) + PackedBytes('x_y_bytes').pack(value.x_y_bytes) + PackedBytes('d').pack(value.d) + PackedBytes('host').pack(value.host)

        padder = IncrementalPadding(padding_size)
        body = padder.pad(encoded)

        if encryptor:
            body = encryptor(body)

        body = PackedBytes('private_key').pack(body)

        return body


    @staticmethod
    def unpack(encoded_bytes: bytes, decryptor: FunctionType=None, already_unpacked: bool=False) -> ('ECDSAPrivateKey', bytes):
        """
        Unpacks bytes into an ECDSAPrivateKey object.

        Parameters:
            encoded_bytes   (bytes): Bytes to be (partially?) decoded.
            already_unpacked (bool): Whether or not to do the initial length-decoding.
        
        Returns:
            (ECDSAPrivateKey, bytes): The decoded object and unused bytes.
        """
        encoded_bytes = Bytes.wrap(encoded_bytes)

        if already_unpacked:
            params, encoded_bytes = encoded_bytes, None
        else:
            params, encoded_bytes = PackedBytes('private_key').unpack(encoded_bytes)

        check_bytes, params = check_decrypt(params, decryptor)

        _header, params = PackedBytes('ecdsa-header').unpack(params)
        curve, params = PackedBytes('curve').unpack(params)
        x_y_bytes, params = PackedBytes('x_y_bytes').unpack(params)
        d, params = PackedBytes('d').unpack(params)
        host, params = PackedBytes('host').unpack(params)

        return ECDSAPrivateKey('private_key', check_bytes=check_bytes, curve=curve, x_y_bytes=x_y_bytes, d=d.int(), host=host), encoded_bytes
