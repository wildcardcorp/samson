from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm, EC_CURVE_MAP, EC_CURVE_MAP_INV
from samson.encoding.general import EncodingScheme
from samson.utilities.bytes import Bytes


class DNSKeyECDSAPrivateKey(DNSKeyPrivateBase):
    ALGS = [DNSKeyAlgorithm.ECDSA_P256_SHA256, DNSKeyAlgorithm.ECDSA_P384_SHA384]

    @staticmethod
    def get_default_alg(ec_key: 'ECDSA') -> DNSKeyAlgorithm:
        return EC_CURVE_MAP_INV[ec_key.G.curve]


    @staticmethod
    def encode(ec_key: 'ECDSA', **kwargs) -> bytes:
        return DNSKeyECDSAPrivateKey.build(
            key=ec_key,
            fields={
                'PrivateKey': ec_key.d
            },
            **kwargs
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        d = fields[b'PrivateKey']

        curve = EC_CURVE_MAP[alg]
        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
        return ecdsa
