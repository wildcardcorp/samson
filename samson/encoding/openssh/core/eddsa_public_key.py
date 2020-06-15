from samson.encoding.openssh.core.packed_bytes import PackedBytes
from samson.utilities.bytes import Bytes

class EdDSAPublicKey(object):
    """
    OpenSSH encoding for an EdDSA public key.
    """

    def __init__(self, name: str, a: int=None):
        """
        Parameters:
            name (str): Name for bookkeeping purposes.
            a    (int): Public int.
        """
        self.name = name
        self.a = a


    def __repr__(self):
        return f"<EdDSAPublicKey: name={self.name}, a={self.a}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def pack(value: 'EdDSAPublicKey') -> Bytes:
        """
        Packs a public key into an OpenSSH-compliant encoding.

        Parameters:
            value (EdDSAPublicKey): Value to encode.
        
        Returns:
            Bytes: Packed bytes.
        """
        encoded = PackedBytes('eddsa-header').pack(b'ssh-ed25519') + PackedBytes('a').pack(value.a)
        encoded = PackedBytes('public_key').pack(encoded)

        return encoded


    @staticmethod
    def unpack(encoded_bytes: bytes, already_unpacked: bool=False) -> ('EdDSAPublicKey', bytes):
        """
        Unpacks bytes into an EdDSAPublicKey object.

        Parameters:
            encoded_bytes   (bytes): Bytes to be (partially?) decoded.
            already_unpacked (bool): Whether or not to do the initial length-decoding.
        
        Returns:
            (EdDSAPublicKey, bytes): The decoded object and unused bytes.
        """
        encoded_bytes = Bytes.wrap(encoded_bytes)

        if already_unpacked:
            params, encoded_bytes = encoded_bytes, None
        else:
            params, encoded_bytes = PackedBytes('public_key').unpack(encoded_bytes)

        _header, params = PackedBytes('eddsa-header').unpack(params)
        a, params = PackedBytes('a').unpack(params)

        return EdDSAPublicKey('public_key', a=a.int()), encoded_bytes
