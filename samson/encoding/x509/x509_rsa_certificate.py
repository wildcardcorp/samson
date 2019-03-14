from samson.encoding.x509.x509_rsa_subject_public_key import X509RSASubjectPublicKey
from samson.encoding.x509.x509_rsa_public_key import X509RSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from pyasn1.type.univ import Any

base_sign_func = lambda pki_obj, hash_obj, data: PKCS1v15RSASigner(pki_obj, hash_obj).sign(data)

class X509RSAParams(object):

    @staticmethod
    def encode(rsa_key):
        return Any(b'\x05\x00')


class X509RSACertificate(X509Certificate):
    ALG_OID = '1.2.840.113549.1.1.1'
    PUB_KEY_ENCODER = X509RSASubjectPublicKey
    PUB_KEY_DECODER = X509RSAPublicKey
    PARAM_ENCODER = X509RSAParams

    SIGNING_ALGS = {
        'sha1WithRSAEncryption': lambda pki_obj, data: base_sign_func(pki_obj, SHA1(), data),
        'sha224WithRSAEncryption': lambda pki_obj, data: base_sign_func(pki_obj, SHA224(), data),
        'sha256WithRSAEncryption': lambda pki_obj, data: base_sign_func(pki_obj, SHA256(), data),
        'sha384WithRSAEncryption': lambda pki_obj, data: base_sign_func(pki_obj, SHA384(), data),
        'sha512WithRSAEncryption': lambda pki_obj, data: base_sign_func(pki_obj, SHA512(), data),
        'sha512-224WithRSAEncryption': lambda pki_obj, data: base_sign_func(pki_obj, SHA512(trunc=224), data),
        'sha512-256WithRSAEncryption': lambda pki_obj, data: base_sign_func(pki_obj, SHA512(trunc=256), data),
    }

    SIGNING_DEFAULT = 'sha256WithRSAEncryption'
