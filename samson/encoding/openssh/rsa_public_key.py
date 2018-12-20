from samson.encoding.openssh.packed_bytes import PackedBytes

class RSAPublicKey(object):
    def __init__(self, name, n=None, e=None):
        self.name = name
        self.n = n
        self.e = e


    def __repr__(self):
        return f"<RSAPublicKey name={self.name}, n={self.n}, e={self.e}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def pack(value):
        return PackedBytes('public_key').pack(
            PackedBytes('rsa-header').pack(b'ssh-rsa') + PackedBytes('e').pack(value.e) + PackedBytes('n').pack(value.n)
        )

    
    @staticmethod
    def unpack(encoded_bytes):
        params, encoded_bytes = PackedBytes('public_key').unpack(encoded_bytes)
        _header, params = PackedBytes('rsa-header').unpack(params)
        e, params = PackedBytes('e').unpack(params)
        n, params = PackedBytes('n').unpack(params)
        return RSAPublicKey('public_key', n=n.int(), e=e.int()), encoded_bytes