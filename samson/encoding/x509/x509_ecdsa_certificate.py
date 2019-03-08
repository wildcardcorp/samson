from samson.encoding.x509.x509_ecdsa_public_key import X509ECDSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.encoding.x509.x509_ecdsa_params import X509ECDSAParams
from samson.encoding.x509.x509_ecdsa_subject_public_key import X509ECDSASubjectPublicKey

class X509ECDSACertificate(X509Certificate):
    ALG_OID = '1.2.840.10045.2.1'
    PUB_KEY_ENCODER = X509ECDSASubjectPublicKey
    PUB_KEY_DECODER = X509ECDSAPublicKey
    PARAM_ENCODER = X509ECDSAParams
