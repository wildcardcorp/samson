from samson.encoding.dns_key.dns_key_base import DNSKeyBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm, EC_CURVE_MAP, EC_CURVE_MAP_INV
from samson.utilities.bytes import Bytes

# https://tools.ietf.org/html/rfc6605
class DNSKeyECDSAPublicKey(DNSKeyBase):
    ALGS = [DNSKeyAlgorithm.ECDSA_P256, DNSKeyAlgorithm.ECDSA_P384]

    @staticmethod
    def get_default_alg(ec_key: 'ECDSA') -> DNSKeyAlgorithm:
        return EC_CURVE_MAP_INV[ec_key.G.curve]


    @staticmethod
    def encode(ec_key: 'ECDSA', **kwargs) -> bytes:
        return DNSKeyECDSAPublicKey.build(ec_key, Bytes(int(ec_key.Q.x)) + Bytes(int(ec_key.Q.y)), **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        alg       = DNSKeyAlgorithm(int(buffer.split(b' ')[2]))
        pub_bytes = DNSKeyBase.get_pub_bytes(buffer)

        d     = 1
        size  = len(pub_bytes) // 2
        x, y  = pub_bytes[:size].int(), pub_bytes[size:].int()
        curve = EC_CURVE_MAP[alg]
    
        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = curve(x, y)

        return ecdsa
