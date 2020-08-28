from samson.encoding.dns_key.dns_key_base import DNSKeyBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm, EC_CURVE_MAP, EC_CURVE_MAP_INV
from samson.utilities.bytes import Bytes

# https://tools.ietf.org/html/rfc6605
class DNSKeyECDSAPublicKey(DNSKeyBase):
    ALGS = [DNSKeyAlgorithm.ECDSA_P256_SHA256, DNSKeyAlgorithm.ECDSA_P384_SHA384]

    @staticmethod
    def get_default_alg(ec_key: 'ECDSA') -> DNSKeyAlgorithm:
        return EC_CURVE_MAP_INV[ec_key.G.curve]


    @staticmethod
    def encode(ec_key: 'ECDSA', **kwargs) -> bytes:
        size = (ec_key.G.curve.order.bit_length() + 7) // 8
        return DNSKeyECDSAPublicKey.build(ec_key, Bytes(int(ec_key.Q.x)).zfill(size) + Bytes(int(ec_key.Q.y)).zfill(size), **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        alg       = DNSKeyAlgorithm(int(DNSKeyBase.prune_buffer(buffer).split(b' ')[2]))
        pub_bytes = DNSKeyBase.get_pub_bytes(buffer)

        size  = len(pub_bytes) // 2
        x, y  = pub_bytes[:size].int(), pub_bytes[size:].int()
        curve = EC_CURVE_MAP[alg]
    
        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=1)
        ecdsa.Q = curve(x, y)

        return ecdsa
