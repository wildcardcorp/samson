from samson.encoding.x509.x509_ecdsa_public_key import X509ECDSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.encoding.x509.x509_ecdsa_params import X509ECDSAParams
from samson.encoding.x509.x509_ecdsa_subject_public_key import X509ECDSASubjectPublicKey
from samson.encoding.x509.x509_dsa_certificate import sign
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512

class X509ECDSACertificate(X509Certificate):
    ALG_OID = '1.2.840.10045.2.1'
    PUB_KEY_ENCODER = X509ECDSASubjectPublicKey
    PUB_KEY_DECODER = X509ECDSAPublicKey
    PARAM_ENCODER = X509ECDSAParams

    SIGNING_ALGS = {
        'ecdsa-with-SHA224': lambda pki_obj, data: sign(pki_obj, SHA224(), data),
        'ecdsa-with-SHA256': lambda pki_obj, data: sign(pki_obj, SHA256(), data),
        'ecdsa-with-SHA384': lambda pki_obj, data: sign(pki_obj, SHA384(), data),
        'ecdsa-with-SHA512': lambda pki_obj, data: sign(pki_obj, SHA512(), data),
    }


    SIGNING_DEFAULT = 'ecdsa-with-SHA256'
