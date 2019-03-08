from samson.encoding.x509.x509_dsa_public_key import X509DSAPublicKey
from samson.encoding.x509.x509_dsa_subject_public_key import X509DSASubjectPublicKey
from samson.encoding.x509.x509_dsa_params import X509DSAParams
from samson.encoding.x509.x509_certificate import X509Certificate

class X509DSACertificate(X509Certificate):
    ALG_OID = '1.2.840.10040.4.1'
    PUB_KEY_ENCODER = X509DSASubjectPublicKey
    PUB_KEY_DECODER = X509DSAPublicKey
    PARAM_ENCODER = X509DSAParams
