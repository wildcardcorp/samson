from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.dns_key_public_base import DNSKeyPublicBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm, ED_CURVE_MAP, ED_CURVE_MAP_INV

class DNSKeyEdDSAKey(object):
    ALGS = [DNSKeyAlgorithm.ED25519, DNSKeyAlgorithm.ED448]

    @staticmethod
    def get_default_alg(ed_key: 'EdDSA') -> DNSKeyAlgorithm:
        return ED_CURVE_MAP_INV[ed_key.curve]



class DNSKeyEdDSAPrivateKey(DNSKeyPrivateBase, DNSKeyEdDSAKey):

    def encode(self) -> bytes:
        return self.build(
            fields={
                'PrivateKey': self.key.d
            }
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'EdDSA':
        from samson.public_key.eddsa import EdDSA
        version, alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        d = fields[b'PrivateKey'].int()

        curve = ED_CURVE_MAP[alg]
        eddsa = EdDSA(d=d, curve=curve)
        full_key = DNSKeyEdDSAPrivateKey(eddsa, alg, version, *DNSKeyPrivateBase.get_metadata(fields))
        return full_key



# https://tools.ietf.org/html/rfc6605
class DNSKeyEdDSAPublicKey(DNSKeyPublicBase, DNSKeyEdDSAKey):

    def encode(self, spacing: int=32, **kwargs) -> bytes:
        return self.build(self.key.encode_point(self.key.A), spacing=spacing)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ed_key':
        from samson.public_key.eddsa import EdDSA
        alg       = DNSKeyAlgorithm(int(DNSKeyPublicBase.prune_buffer(buffer).split(b' ')[2]))
        pub_bytes = DNSKeyPublicBase.get_pub_bytes(buffer)

        curve    = ED_CURVE_MAP[alg]
        eddsa    = EdDSA(d=1, curve=curve)
        eddsa.A  = eddsa.decode_point(pub_bytes)
        full_key = DNSKeyEdDSAPublicKey(eddsa, *DNSKeyPublicBase.get_metadata(buffer))
        return full_key
