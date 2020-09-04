from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.dns_key_public_base import DNSKeyPublicBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm, EC_CURVE_MAP, EC_CURVE_MAP_INV
from samson.utilities.bytes import Bytes

class DNSKeyECDSAKey(object):
    ALGS = [DNSKeyAlgorithm.ECDSA_P256_SHA256, DNSKeyAlgorithm.ECDSA_P384_SHA384]

    @staticmethod
    def get_default_alg(ec_key: 'ECDSA') -> DNSKeyAlgorithm:
        if ec_key.G.curve not in EC_CURVE_MAP_INV:
            raise NotImplementedError(f'{ec_key.G.curve} is not a valid curve for DNS_KEY')

        return EC_CURVE_MAP_INV[ec_key.G.curve]



class DNSKeyECDSAPrivateKey(DNSKeyPrivateBase, DNSKeyECDSAKey):

    def encode(self) -> bytes:
        return self.build(
            fields={
                'PrivateKey': self.key.d
            }
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        version, alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        d = fields[b'PrivateKey']

        curve    = EC_CURVE_MAP[alg]
        ecdsa    = ECDSA(G=curve.G, hash_obj=None, d=d)
        full_key = DNSKeyECDSAPrivateKey(ecdsa, alg, version, *DNSKeyPrivateBase.get_metadata(fields))
        return full_key



# https://tools.ietf.org/html/rfc6605
class DNSKeyECDSAPublicKey(DNSKeyPublicBase, DNSKeyECDSAKey):

    def encode(self, spacing: int=32) -> bytes:
        size = (self.key.G.curve.order.bit_length() + 7) // 8
        return self.build(Bytes(int(self.key.Q.x)).zfill(size) + Bytes(int(self.key.Q.y)).zfill(size), spacing=spacing)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        alg       = DNSKeyAlgorithm(int(DNSKeyPublicBase.prune_buffer(buffer).split(b' ')[2]))
        pub_bytes = DNSKeyPublicBase.get_pub_bytes(buffer)

        size  = len(pub_bytes) // 2
        x, y  = pub_bytes[:size].int(), pub_bytes[size:].int()
        curve = EC_CURVE_MAP[alg]

        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=1)
        ecdsa.Q = curve(x, y)

        full_key = DNSKeyECDSAPublicKey(ecdsa, *DNSKeyPublicBase.get_metadata(buffer))
        return full_key
