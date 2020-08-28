from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm, ED_CURVE_MAP, ED_CURVE_MAP_INV
from samson.encoding.general import EncodingScheme
from samson.utilities.bytes import Bytes


class DNSKeyEdDSAPrivateKey(DNSKeyPrivateBase):
    ALGS = [DNSKeyAlgorithm.ED25519, DNSKeyAlgorithm.ED448]


    @staticmethod
    def get_default_alg(ed_key: 'EdDSA') -> DNSKeyAlgorithm:
        return ED_CURVE_MAP_INV[ed_key.curve]


    @staticmethod
    def encode(ed_key: 'EdDSA', **kwargs) -> bytes:
        return DNSKeyEdDSAPrivateKey.build(
            key=ed_key,
            fields={
                'PrivateKey': ed_key.d
            },
            **kwargs
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'EdDSA':
        from samson.public_key.eddsa import EdDSA
        alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        d = fields[b'PrivateKey'].int()

        curve = ED_CURVE_MAP[alg]
        eddsa = EdDSA(d=d, curve=curve)
        return eddsa
