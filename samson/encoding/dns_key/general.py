from enum import Enum, IntFlag
from samson.math.algebra.curves.named import P256, P384, EdwardsCurve25519, EdwardsCurve448

# https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
class DNSKeyAlgorithm(Enum):
    RSA_MD5 = 1
    DH = 2
    DSA = 3
    RSA_SHA1 = 5
    DSA_SHA1_NSEC3 = 6
    RSA_SHA1_NSEC3 = 7
    RSA_SHA256 = 8
    RSA_SHA512 = 10
    ECDSA_P256_SHA256 = 13
    ECDSA_P384_SHA384 = 14
    ED25519 = 15
    ED448 = 16


EC_CURVE_MAP = {
    DNSKeyAlgorithm.ECDSA_P256_SHA256: P256,
    DNSKeyAlgorithm.ECDSA_P384_SHA384: P384,
}

EC_CURVE_MAP_INV = {v:k for k,v in EC_CURVE_MAP.items()}


ED_CURVE_MAP = {
    DNSKeyAlgorithm.ED25519: EdwardsCurve25519,
    DNSKeyAlgorithm.ED448: EdwardsCurve448,
}

ED_CURVE_MAP_INV = {v:k for k,v in ED_CURVE_MAP.items()}


# https://tools.ietf.org/html/rfc4034#section-2.1
# Converted from little endian
class DNSKeyFlags(IntFlag):
    SECURE_ENTRY_POINT = 2**0
    ZONE_KEY = 2**8



def to_wire(key: bytes):
    flags, proto, alg = key.split(b' ')[:3]

    flags = Bytes(int(flags)).zfill(2)
    proto = Bytes(int(proto)).zfill(1)
    alg   = Bytes(int(alg)).zfill(1)

    return flags + proto + alg + DNSKeyDHublicKey.get_pub_bytes(key)


def calculate_key_tag(key: bytes):
    # https://tools.ietf.org/html/rfc4034#appendix-B
    acc = 0
    for i in range(len(key)):
        acc += key[i] if (i & 1) else key[i] << 8

    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF
