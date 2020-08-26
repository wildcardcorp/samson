from samson.encoding.general import EncodingScheme
from samson.encoding.dns_key.general import DNSKeyAlgorithm, DNSKeyFlags

class DNSKeyBase(object):
    ALGS = None

    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        try:
            split   = buffer.split(b' ')
            alg     = int(split[2])
            pub_key = b''.join(buffer.split(b' ')[3:])

            return DNSKeyAlgorithm(alg) in cls.ALGS and EncodingScheme.BASE64 in EncodingScheme.get_valid_charsets(pub_key)

        except Exception as _:
            return False


    @classmethod
    def build(cls, pub_key: object, pub_bytes: bytes, **kwargs) -> bytes:
        alg   = kwargs.get('alg', cls.get_default_alg(pub_key))
        proto = kwargs.get('proto', 3)
        flags = kwargs.get('flags', DNSKeyFlags.ZONE_KEY)

        return f'{int(flags)} {proto} {alg.value} '.encode('utf-8') + b' '.join(EncodingScheme.BASE64.encode(pub_bytes).chunk(32, allow_partials=True))


    @staticmethod
    def get_pub_bytes(buffer: bytes):
        pub_key   = b''.join(buffer.split(b' ')[3:])
        return EncodingScheme.BASE64.decode(pub_key)
