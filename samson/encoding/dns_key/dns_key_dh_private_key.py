from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.encoding.general import EncodingScheme
from samson.utilities.bytes import Bytes


class DNSKeyDHPrivateKey(DNSKeyPrivateBase):
    ALGS = [DNSKeyAlgorithm.DH]


    @staticmethod
    def get_default_alg(dh_key: 'DiffieHellman') -> DNSKeyAlgorithm:
        return DNSKeyAlgorithm.DH


    @staticmethod
    def encode(dh_key: 'DiffieHellman', **kwargs) -> bytes:
        return DNSKeyDHPrivateKey.build(
            key=dh_key,
            fields={
                'Prime(p)': dh_key.p,
                'Generator(g)': dh_key.g,
                'Private_value(x)': dh_key.key,
                'Public_value(y)': dh_key.y
            },
            **kwargs
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'DiffieHellman':
        from samson.protocols.diffie_hellman import DiffieHellman

        alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        p = fields[b'Prime(p)'].int()
        g = fields[b'Generator(g)'].int()
        x = fields[b'Private_value(x)'].int()
        y = fields[b'Public_value(y)'].int()
        return DiffieHellman(g=g, p=p, key=x, y=y)
