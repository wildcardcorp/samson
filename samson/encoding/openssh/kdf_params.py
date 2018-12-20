from samson.encoding.openssh.packed_bytes import PackedBytes
from samson.encoding.openssh.literal import Literal


class KDFParams(object):
    def __init__(self, name, salt=None, rounds=None):
        self.name = name
        self.salt = salt
        self.rounds = rounds


    def __repr__(self):
        return f"<KDFParams name={self.name}, salt={self.salt}, rounds={self.rounds}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def pack(value):
        return PackedBytes('kdf_params').pack(PackedBytes('salt').pack(value.salt) + Literal('rounds').pack(value.rounds), force_pack=True)

    
    @staticmethod
    def unpack(encoded_bytes):
        params, encoded_bytes = PackedBytes('kdf_params').unpack(encoded_bytes)
        salt, params = PackedBytes('salt').unpack(params)
        rounds, params = Literal('rounds').unpack(params)
        return KDFParams('kdf_params', salt=salt, rounds=rounds), encoded_bytes