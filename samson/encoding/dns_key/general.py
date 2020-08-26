from enum import Enum, IntFlag
from samson.math.algebra.curves.named import P256, P384, EdwardsCurve25519, EdwardsCurve448

# https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
class DNSKeyAlgorithm(Enum):
    RSA_MD5 = 1
    DIFFIE_HELLMAN = 2
    DSA = 3
    RSA_SHA1 = 5
    DSA_SHA1_NSEC3 = 6
    RSA_SHA1_NSEC3 = 7
    RSA_SHA256 = 8
    RSA_SHA512 = 10
    ECDSA_P256 = 13
    ECDSA_P384 = 14
    ED25519 = 15
    ED448 = 16


EC_CURVE_MAP = {
    DNSKeyAlgorithm.ECDSA_P256: P256,
    DNSKeyAlgorithm.ECDSA_P384: P384,
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
    ZONE_KEY = 2**8
    SECURE_ENTRY_POINT = 2**0
