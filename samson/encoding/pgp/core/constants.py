from enum import Enum

# https://tools.ietf.org/html/rfc4880#section-9

class PGPPublicKeyAlgo(Enum):
    RSA_ENC_OR_SIG = 1
    RSA_ENC        = 2
    RSA_SIG        = 3
    ELGAMAL_ENC    = 16
    DSA            = 17


class PGPSymmetricAlgo(Enum):
    PLAINTEXT    = 0
    IDEA         = 1
    TRIPLE_DES   = 2
    CAST5        = 3
    BLOWFISH     = 4
    AES_128      = 7
    AES_192      = 8
    AES_256      = 9
    TWOFISH      = 10
    CAMELLIA_128 = 11
    CAMELLIA_192 = 12
    CAMELLIA_256 = 13


class PGPCompressionAlgo(Enum):
    UNCOMPRESSED = 0
    ZIP          = 1
    ZLIB         = 2
    BZIP2        = 3


class PGPHashAlgo(Enum):
    MD5       = 1
    SHA1      = 2
    RIPEMD160 = 3
    SHA256    = 8
    SHA384    = 9
    SHA512    = 10
    SHA224    = 11
