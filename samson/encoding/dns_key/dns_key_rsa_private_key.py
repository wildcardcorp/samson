from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.encoding.general import EncodingScheme
from samson.utilities.bytes import Bytes


class DNSKeyRSAPrivateKey(DNSKeyPrivateBase):
    ALGS = [DNSKeyAlgorithm.RSA_MD5, DNSKeyAlgorithm.RSA_SHA1, DNSKeyAlgorithm.RSA_SHA1_NSEC3, DNSKeyAlgorithm.RSA_SHA256, DNSKeyAlgorithm.RSA_SHA512]


    @staticmethod
    def get_default_alg(rsa_key: 'RSA') -> DNSKeyAlgorithm:
        return DNSKeyAlgorithm.RSA_SHA256


    @staticmethod
    def encode(rsa_key: 'RSA', **kwargs) -> bytes:
        return DNSKeyRSAPrivateKey.build(
            key=rsa_key,
            fields={
                'Modulus': rsa_key.n,
                'PublicExponent': rsa_key.e,
                'PrivateExponent': rsa_key.alt_d,
                'Prime1': rsa_key.p,
                'Prime2': rsa_key.q,
                'Exponent1': rsa_key.dP,
                'Exponent2': rsa_key.dQ,
                'Coefficient': rsa_key.Qi
            },
            **kwargs
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.public_key.rsa import RSA

        alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        e = fields[b'PublicExponent'].int()
        p = fields[b'Prime1'].int()
        q = fields[b'Prime2'].int()
        return RSA(p=p, q=q, e=e)
