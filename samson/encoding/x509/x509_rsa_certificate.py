from samson.encoding.x509.x509_rsa_subject_public_key import X509RSASubjectPublicKey
from samson.encoding.x509.x509_rsa_public_key import X509RSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.encoding.x509.x509_certificate_signing_request import X509CertificateSigningRequest
from samson.encoding.x509.x509_signature import X509Signature
from samson.encoding.x509.oids import SigningAlgOID
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from samson.hashes.md5 import MD5
from samson.hashes.md2 import MD2
from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Any, BitString
from enum import Enum



class X509RSASignature(X509Signature):
    def sign(self, pki_obj, data):
        signed = self._build_signer(pki_obj).sign(data)
        return BitString(bin(signed.int())[2:].zfill(pki_obj.n.bit_length()))
    
    def _build_signer(self, pki_obj):
        from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
        return PKCS1v15RSASigner(pki_obj, self.hash_obj)


    def parse_signature(self, pki_obj, sig):
        return self._build_signer(pki_obj).parse_signature(sig)


    def verify(self, pki_obj, data, sig):
        return self._build_signer(pki_obj).verify(data, Bytes(int(sig)))


class X509RSASigningAlgorithms(Enum):
    md2WithRSAEncryption        = X509RSASignature(SigningAlgOID.MD2_WITH_RSA_ENCRYPTION, MD2())
    md5WithRSAEncryption        = X509RSASignature(SigningAlgOID.MD5_WITH_RSA_ENCRYPTION, MD5())
    sha1WithRSAEncryption       = X509RSASignature(SigningAlgOID.SHA1_WITH_RSA_ENCRYPTION, SHA1())
    sha224WithRSAEncryption     = X509RSASignature(SigningAlgOID.SHA224_WITH_RSA_ENCRYPTION, SHA224())
    sha256WithRSAEncryption     = X509RSASignature(SigningAlgOID.SHA256_WITH_RSA_ENCRYPTION, SHA256())
    sha384WithRSAEncryption     = X509RSASignature(SigningAlgOID.SHA384_WITH_RSA_ENCRYPTION, SHA384())
    sha512WithRSAEncryption     = X509RSASignature(SigningAlgOID.SHA512_WITH_RSA_ENCRYPTION, SHA512())
    sha512_224WithRSAEncryption = X509RSASignature(SigningAlgOID.SHA512_224_WITH_RSA_ENCRYPTION, SHA512(trunc=224))
    sha512_256WithRSAEncryption = X509RSASignature(SigningAlgOID.SHA512_256_WITH_RSA_ENCRYPTION, SHA512(trunc=256))


class X509RSAParams(object):

    @staticmethod
    def encode(rsa_key):
        return Any(b'\x05\x00')


class X509RSACertificate(X509Certificate):
    ALG_OID = '1.2.840.113549.1.1.1'
    PUB_KEY_ENCODER = X509RSASubjectPublicKey
    PUB_KEY_DECODER = X509RSAPublicKey
    PARAM_ENCODER   = X509RSAParams


class X509RSACertificateSigningRequest(X509CertificateSigningRequest, X509RSACertificate):
    pass
