from samson.encoding.dns_key.dns_key_base import DNSKeyBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm, ED_CURVE_MAP, ED_CURVE_MAP_INV
from samson.utilities.bytes import Bytes

# https://tools.ietf.org/html/rfc6605
class DNSKeyEdDSAPublicKey(DNSKeyBase):
    ALGS = [DNSKeyAlgorithm.ED25519, DNSKeyAlgorithm.ED448]

    @staticmethod
    def get_default_alg(ed_key: 'EdDSA') -> DNSKeyAlgorithm:
        return ED_CURVE_MAP_INV[ed_key.curve]


    @staticmethod
    def encode(ed_key: 'EdDSA', **kwargs) -> bytes:
        return DNSKeyEdDSAPublicKey.build(ed_key, ed_key.encode_point(ed_key.A), **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ed_key':
        from samson.public_key.eddsa import EdDSA
        alg       = DNSKeyAlgorithm(int(DNSKeyBase.prune_buffer(buffer).split(b' ')[2]))
        pub_bytes = DNSKeyBase.get_pub_bytes(buffer)

        curve = ED_CURVE_MAP[alg]
        eddsa = EdDSA(d=1, curve=curve)
        eddsa.A = eddsa.decode_point(pub_bytes)
        return eddsa
