from samson.encoding.openssh.packed_bytes import PackedBytes
from samson.utilities.bytes import Bytes

class ECDSAPublicKey(object):
    """
    OpenSSH encoding for an ECDSA public key.
    """

    def __init__(self, name: str, curve: bytes=None, x_y_bytes: bytes=None):
        """
        Parameters:
            name        (str): Name for bookkeeping purposes.
            curve     (bytes): Elliptical curve name.
            x_y_bytes (bytes): Byte encoding of x and y.
        """
        self.name = name
        self.curve = curve
        self.x_y_bytes = x_y_bytes


    def __repr__(self):
        return f"<ECDSAPublicKey name={self.name}, curve={self.curve}, x_y_bytes={self.x_y_bytes}>"

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
        encoded = PackedBytes('ecdsa-header').pack(b'ecdsa-sha2-' + value.curve) + PackedBytes('curve').pack(value.curve) + PackedBytes('x_y_bytes').pack(value.x_y_bytes)
        encoded = PackedBytes('public_key').pack(encoded)

        return encoded


    @staticmethod
    def unpack(encoded_bytes: bytes, already_unpacked: bool=False) -> (object, bytes):
        """
        Unpacks bytes into an ECDSAPublicKey object.

        Parameters:
            encoded_bytes   (bytes): Bytes to be (partially?) decoded.
            already_unpacked (bool): Whether or not to do the initial length-decoding.
        
        Returns:
            (ECDSAPublicKey, bytes): The decoded object and unused bytes.
        """
        encoded_bytes = Bytes.wrap(encoded_bytes)

        if already_unpacked:
            params, encoded_bytes = encoded_bytes, None
        else:
            params, encoded_bytes = PackedBytes('public_key').unpack(encoded_bytes)

        _header, params = PackedBytes('ecdsa-header').unpack(params)
        curve, params = PackedBytes('curve').unpack(params)
        x_y_bytes, params = PackedBytes('x_y_bytes').unpack(params)

        return ECDSAPublicKey('public_key', curve=curve, x_y_bytes=x_y_bytes), encoded_bytes
