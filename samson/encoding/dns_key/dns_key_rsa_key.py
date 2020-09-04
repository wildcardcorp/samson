from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.dns_key_public_base import DNSKeyPublicBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.utilities.bytes import Bytes

class DNSKeyRSABase(object):
    ALGS = [DNSKeyAlgorithm.RSA_MD5, DNSKeyAlgorithm.RSA_SHA1, DNSKeyAlgorithm.RSA_SHA1_NSEC3, DNSKeyAlgorithm.RSA_SHA256, DNSKeyAlgorithm.RSA_SHA512]

    @staticmethod
    def get_default_alg(rsa_key: 'RSA') -> DNSKeyAlgorithm:
        return DNSKeyAlgorithm.RSA_SHA256


class DNSKeyRSAPrivateKey(DNSKeyPrivateBase, DNSKeyRSABase):

    def encode(self) -> bytes:
        return self.build(
            fields={
                'Modulus': self.key.n,
                'PublicExponent': self.key.e,
                'PrivateExponent': self.key.alt_d,
                'Prime1': self.key.p,
                'Prime2': self.key.q,
                'Exponent1': self.key.dP,
                'Exponent2': self.key.dQ,
                'Coefficient': self.key.Qi
            }
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.public_key.rsa import RSA

        version, alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        e = fields[b'PublicExponent'].int()
        p = fields[b'Prime1'].int()
        q = fields[b'Prime2'].int()

        full_key = DNSKeyRSAPrivateKey(RSA(p=p, q=q, e=e), alg, version, *DNSKeyPrivateBase.get_metadata(fields))
        return full_key



# https://tools.ietf.org/html/rfc5702
class DNSKeyRSAPublicKey(DNSKeyPublicBase, DNSKeyRSABase):

    def encode(self, spacing: int=32, **kwargs) -> bytes:
        n = Bytes(self.key.n)
        e = Bytes(self.key.e)

        return self.build(Bytes(len(e)) + e + n, spacing=spacing)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.public_key.rsa import RSA
        pub_bytes = DNSKeyPublicBase.get_pub_bytes(buffer)
        e_size = pub_bytes[0]

        e = pub_bytes[1:1+e_size].int()
        n = pub_bytes[1+e_size:].int()

        rsa      = RSA(n=n, e=e)
        full_key = DNSKeyRSAPublicKey(rsa, *DNSKeyPublicBase.get_metadata(buffer))
        return full_key
