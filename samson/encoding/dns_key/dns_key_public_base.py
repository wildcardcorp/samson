from samson.encoding.general import EncodingScheme
from samson.encoding.dns_key.general import DNSKeyAlgorithm, DNSKeyFlags
from samson.core.base_object import BaseObject
import re

METADATA_RE = re.compile(b'[0-9]{1,3} 3 [0-9]{1,2}')

class DNSKeyPublicBase(BaseObject):

    def __init__(self, key: object, alg: DNSKeyAlgorithm=None, proto: int=3, flags: DNSKeyFlags=DNSKeyFlags.ZONE_KEY, **kwargs):
        self.key   = key
        self.alg   = alg or self.get_default_alg(key)
        self.proto = proto

        if type(flags) is int:
            flags = DNSKeyFlags(flags)

        self.flags = flags


    @staticmethod
    def prune_buffer(buffer: bytes) -> bytes:
        match = METADATA_RE.search(buffer)
        start = match.start() if match else 0
        return buffer[start:]


    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        try:
            split   = DNSKeyPublicBase.prune_buffer(buffer).split(b' ')
            alg     = int(split[2])
            pub_key = b''.join(buffer.split(b' ')[3:])

            return DNSKeyAlgorithm(alg) in cls.ALGS and EncodingScheme.BASE64 in EncodingScheme.get_valid_charsets(pub_key)

        except Exception as _:
            return False


    def build(self, pub_bytes: bytes, spacing: int=32) -> bytes:
        alg = self.alg

        if type(alg) is DNSKeyAlgorithm:
            alg = alg.value

        return f'{int(self.flags)} {self.proto} {alg} '.encode('utf-8') + b' '.join(EncodingScheme.BASE64.encode(pub_bytes).chunk(spacing, allow_partials=True))


    @staticmethod
    def get_metadata(buffer: bytes):
        flags, proto, alg = [int(item) for item in DNSKeyPublicBase.prune_buffer(buffer).split(b' ')[:3]]
        return alg, proto, flags


    @staticmethod
    def get_pub_bytes(buffer: bytes):
        pub_key   = b''.join(DNSKeyPublicBase.prune_buffer(buffer).split(b' ')[3:])
        return EncodingScheme.BASE64.decode(pub_key)
