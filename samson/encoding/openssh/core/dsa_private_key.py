from samson.encoding.openssh.core.packed_bytes import PackedBytes
from samson.encoding.openssh.core.literal import Literal
from samson.encoding.openssh.general import check_decrypt
from samson.padding.incremental_padding import IncrementalPadding
from samson.utilities.bytes import Bytes
from types import FunctionType


class DSAPrivateKey(object):
    """
    OpenSSH encoding for an DSA private key.
    """

    def __init__(self, name: str, check_bytes: bytes=None, p: int=None, q: int=None, g: int=None, y: int=None, x: int=None, host: bytes=None):
        """
        Parameters:
            name          (str): Name for bookkeeping purposes.
            check_bytes (bytes): Four random bytes repeated for OpenSSH to check if the decryption worked.
            p             (int): Prime modulus.
            q             (int): Prime modulus.
            g             (int): Generator.
            y             (int): Public key.
            x             (int): Private key.
            host        (bytes): Host the key was generated on.
        """
        self.name = name
        self.check_bytes = check_bytes or Bytes.random(4) * 2
        self.p = p
        self.q = q
        self.g = g
        self.y = y
        self.x = x
        self.host = host


    def __repr__(self):
        return f"<DSAPrivateKey: name={self.name}, p={self.p}, q={self.q}, g={self.g}, y={self.y}, x={self.x}, host={self.host}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def pack(value: bytes, encryptor: FunctionType=None, padding_size: int=8) -> Bytes:
        """
        Packs a private key into an OpenSSH-compliant encoding.

        Parameters:
            value      (bytes): Value to encode.
            encryptor   (func): (Optional) Function to use as the encryptor.
            padding_size (int): The block size to pad to. Usually 8 unless you're encrypting.
        
        Returns:
            Bytes: Packed bytes.
        """
        check_bytes = Literal('check_bytes', length=8).pack(value.check_bytes)
        encoded = check_bytes + PackedBytes('dsa-header').pack(b'ssh-dss') + PackedBytes('p').pack(value.p) + PackedBytes('q').pack(value.q) + PackedBytes('g').pack(value.g) + PackedBytes('y').pack(value.y) + PackedBytes('x').pack(value.x) + PackedBytes('host').pack(value.host)

        padder = IncrementalPadding(padding_size)
        body = padder.pad(encoded)

        if encryptor:
            body = encryptor(body)

        return PackedBytes('private_key').pack(body)


    @staticmethod
    def unpack(encoded_bytes: bytes, decryptor: FunctionType=None, already_unpacked: bool=False) -> (object, bytes):
        """
        Unpacks bytes into an DSAPrivateKey object.

        Parameters:
            encoded_bytes   (bytes): Bytes to be (partially?) decoded.
            already_unpacked (bool): Whether or not to do the initial length-decoding.
        
        Returns:
            (DSAPrivateKey, bytes): The decoded object and unused bytes.
        """
        encoded_bytes = Bytes.wrap(encoded_bytes)

        if already_unpacked:
            params, encoded_bytes = encoded_bytes, None
        else:
            params, encoded_bytes = PackedBytes('private_key').unpack(encoded_bytes)

        check_bytes, params = check_decrypt(params, decryptor)

        _header, params = PackedBytes('dsa-header').unpack(params)
        p, params = PackedBytes('p').unpack(params)
        q, params = PackedBytes('q').unpack(params)
        g, params = PackedBytes('g').unpack(params)
        y, params = PackedBytes('y').unpack(params)
        x, params = PackedBytes('x').unpack(params)
        host, params = PackedBytes('host').unpack(params)
        return DSAPrivateKey('private_key', check_bytes=check_bytes, p=p.int(), q=q.int(), g=g.int(), y=y.int(), x=x.int(), host=host), encoded_bytes
