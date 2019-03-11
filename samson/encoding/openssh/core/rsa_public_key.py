from samson.encoding.openssh.core.packed_bytes import PackedBytes
from samson.utilities.bytes import Bytes

class RSAPublicKey(object):
    """
    OpenSSH encoding for an RSA public key.
    """

    def __init__(self, name: str, n: int=None, e: int=None):
        """
        Parameters:
            name (str): Name for bookkeeping purposes.
            n    (int): RSA modulus.
            e    (int): RSA public exponent.
        """
        self.name = name
        self.n = n
        self.e = e


    def __repr__(self):
        return f"<RSAPublicKey name={self.name}, n={self.n}, e={self.e}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def pack(value: object) -> Bytes:
        """
        Packs a public key into an OpenSSH-compliant encoding.

        Parameters:
            value (bytes): Value to encode.
        
        Returns:
            Bytes: Packed bytes.
        """
        return PackedBytes('public_key').pack(
            PackedBytes('rsa-header').pack(b'ssh-rsa') + PackedBytes('e').pack(value.e) + PackedBytes('n').pack(value.n)
        )


    @staticmethod
    def unpack(encoded_bytes: bytes, already_unpacked: bool=False) -> (object, bytes):
        """
        Unpacks bytes into an RSAPublicKey object.

        Parameters:
            encoded_bytes   (bytes): Bytes to be (partially?) decoded.
            already_unpacked (bool): Whether or not to do the initial length-decoding.
        
        Returns:
            (RSAPublicKey, bytes): The decoded object and unused bytes.
        """
        if already_unpacked:
            params, encoded_bytes = Bytes.wrap(encoded_bytes), None
        else:
            params, encoded_bytes = PackedBytes('public_key').unpack(encoded_bytes)

        _header, params = PackedBytes('rsa-header').unpack(params)
        e, params = PackedBytes('e').unpack(params)
        n, params = PackedBytes('n').unpack(params)
        return RSAPublicKey('public_key', n=n.int(), e=e.int()), encoded_bytes
