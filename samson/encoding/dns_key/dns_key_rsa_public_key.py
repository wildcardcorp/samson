from samson.encoding.dns_key.dns_key_base import DNSKeyBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.utilities.bytes import Bytes

# https://tools.ietf.org/html/rfc5702
class DNSKeyRSAPublicKey(DNSKeyBase):
    ALGS = [DNSKeyAlgorithm.RSA_MD5, DNSKeyAlgorithm.RSA_SHA1, DNSKeyAlgorithm.RSA_SHA1_NSEC3, DNSKeyAlgorithm.RSA_SHA256, DNSKeyAlgorithm.RSA_SHA512]


    @staticmethod
    def get_default_alg(rsa_key: 'RSA') -> DNSKeyAlgorithm:
        return DNSKeyAlgorithm.RSA_SHA256


    @staticmethod
    def encode(rsa_key: 'RSA', **kwargs) -> bytes:
        n = Bytes(rsa_key.n)
        e = Bytes(rsa_key.e)

        return DNSKeyRSAPublicKey.build(rsa_key, Bytes(len(e)) + e + n, **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.public_key.rsa import RSA
        pub_bytes = DNSKeyBase.get_pub_bytes(buffer)
        e_size = pub_bytes[0]

        e = pub_bytes[1:1+e_size].int()
        n = pub_bytes[1+e_size:].int()

        rsa = RSA(n=n, e=e)
        return rsa
