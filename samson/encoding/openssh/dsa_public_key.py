from samson.encoding.openssh.packed_bytes import PackedBytes
from samson.utilities.bytes import Bytes

class DSAPublicKey(object):
    """
    OpenSSH encoding for an DSA public key.
    """

    def __init__(self, name: str, p: int=None, q: int=None, g: int=None, y: int=None):
        """
        Parameters:
            name (str): Name for bookkeeping purposes.
            p    (int): Prime modulus.
            q    (int): Prime modulus.
            g    (int): Generator.
            y    (int): Public key.
        """
        self.name = name
        self.p = p
        self.q = q
        self.g = g
        self.y = y


    def __repr__(self):
        return f"<DSAPublicKey name={self.name}, p={self.p}, q={self.q}, g={self.g}, y={self.y}>"

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
        encoded = PackedBytes('dsa-header').pack(b'ssh-dss') + PackedBytes('p').pack(value.p) + PackedBytes('q').pack(value.q) + PackedBytes('g').pack(value.g) + PackedBytes('y').pack(value.y)
        encoded = PackedBytes('public_key').pack(encoded)

        return encoded


    @staticmethod
    def unpack(encoded_bytes: bytes, already_unpacked: bool=False) -> (object, bytes):
        """
        Unpacks bytes into an DSAPublicKey object.

        Parameters:
            encoded_bytes   (bytes): Bytes to be (partially?) decoded.
            already_unpacked (bool): Whether or not to do the initial length-decoding.
        
        Returns:
            (DSAPublicKey, bytes): The decoded object and unused bytes.
        """
        encoded_bytes = Bytes.wrap(encoded_bytes)

        if already_unpacked:
            params, encoded_bytes = encoded_bytes, None
        else:
            params, encoded_bytes = PackedBytes('public_key').unpack(encoded_bytes)

        _header, params = PackedBytes('dsa-header').unpack(params)
        p, params = PackedBytes('p').unpack(params)
        q, params = PackedBytes('q').unpack(params)
        g, params = PackedBytes('g').unpack(params)
        y, params = PackedBytes('y').unpack(params)

        if already_unpacked:
            encoded_bytes = params

        return DSAPublicKey('public_key', p=p.int(), q=q.int(), g=g.int(), y=y.int()), encoded_bytes
