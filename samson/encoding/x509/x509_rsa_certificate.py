from samson.encoding.x509.x509_rsa_subject_public_key import X509RSASubjectPublicKey
from samson.encoding.x509.x509_rsa_public_key import X509RSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Any, BitString
from enum import Enum


class X509RSASignature(object):
    def __init__(self, name, hash_obj):
        self.name     = name
        self.hash_obj = hash_obj

    def sign(self, pki_obj, data):
        from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
        signed = PKCS1v15RSASigner(pki_obj, self.hash_obj).sign(data)
        return BitString(bin(signed.int())[2:].zfill(pki_obj.n.bit_length()))

    def verify(self, pki_obj, data, sig):
        from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
        return PKCS1v15RSASigner(pki_obj, self.hash_obj).verify(data, Bytes(int(sig)))


class X509RSASigningAlgorithms(Enum):
    sha1WithRSAEncryption       = X509RSASignature('sha1WithRSAEncryption', SHA1())
    sha224WithRSAEncryption     = X509RSASignature('sha224WithRSAEncryption', SHA224())
    sha256WithRSAEncryption     = X509RSASignature('sha256WithRSAEncryption', SHA256())
    sha384WithRSAEncryption     = X509RSASignature('sha384WithRSAEncryption', SHA384())
    sha512WithRSAEncryption     = X509RSASignature('sha512WithRSAEncryption', SHA512())
    sha512_224WithRSAEncryption = X509RSASignature('sha512-224WithRSAEncryption', SHA512(trunc=224))
    sha512_256WithRSAEncryption = X509RSASignature('sha512-256WithRSAEncryption', SHA512(trunc=256))


class X509RSAParams(object):

    @staticmethod
    def encode(rsa_key):
        return Any(b'\x05\x00')


class X509RSACertificate(X509Certificate):
    ALG_OID = '1.2.840.113549.1.1.1'
    PUB_KEY_ENCODER = X509RSASubjectPublicKey
    PUB_KEY_DECODER = X509RSAPublicKey
    PARAM_ENCODER   = X509RSAParams
