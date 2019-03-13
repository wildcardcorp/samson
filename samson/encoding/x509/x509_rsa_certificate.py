from samson.encoding.x509.x509_rsa_subject_public_key import X509RSASubjectPublicKey
from samson.encoding.x509.x509_rsa_public_key import X509RSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
from samson.hashes.sha2 import SHA256
from pyasn1.type.univ import Any

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
        'sha256WithRSAEncryption': lambda pki_obj, data: PKCS1v15RSASigner(pki_obj, SHA256()).sign(data)
    }

    SIGNING_DEFAULT = 'sha256WithRSAEncryption'