from samson.encoding.openssh.core.packed_bytes import PackedBytes
from samson.encoding.openssh.core.literal import Literal
from samson.utilities.bytes import Bytes

class KDFParams(object):
    """
    Parameters for the KDF in OpenSSH keys.
    """

    def __init__(self, name: str, salt: bytes=None, rounds: bytes=None):
        """
        Parameters:
            name     (str): Name for bookkeeping purposes.
            salt   (bytes): Salt.
            rounds (bytes): Number of rounds to perform.
        """
        self.name = name
        self.salt = salt
        self.rounds = rounds


    def __repr__(self):
        return f"<KDFParams: name={self.name}, salt={self.salt}, rounds={self.rounds}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def pack(value: 'KDFParams') -> Bytes:
        """
        Packs a KDFParams object into bytes.

        Parameters:
            value (KDFParams): KDFParams to encode.
        
        Returns:
            bytes: OpenSSH's encoding of KDFParams.
        """
        return PackedBytes('kdf_params').pack(PackedBytes('salt').pack(value.salt) + Literal('rounds').pack(value.rounds), force_pack=True)


    @staticmethod
    def unpack(encoded_bytes: bytes) -> ('KDFParams', bytes):
        """
        Unpacks bytes into a KDFParams object.

        Parameters:
            encoded_bytes (bytes): Bytes to be (partially?) decoded.
        
        Returns:
            (KDFParams, bytes): The unpacked KDFParams object and unused bytes.
        """
        params, encoded_bytes = PackedBytes('kdf_params').unpack(encoded_bytes)
        salt, params = PackedBytes('salt').unpack(params)
        rounds, params = Literal('rounds').unpack(params)
        return KDFParams('kdf_params', salt=salt, rounds=rounds.int() or b''), encoded_bytes
