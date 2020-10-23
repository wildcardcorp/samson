from samson.encoding.x509.x509_ecdsa_public_key import X509ECDSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.encoding.x509.x509_certificate_signing_request import X509CertificateSigningRequest
from samson.encoding.x509.x509_ecdsa_params import X509ECDSAParams
from samson.encoding.x509.x509_ecdsa_subject_public_key import X509ECDSASubjectPublicKey
from samson.encoding.x509.x509_dsa_certificate import X509DSASignature
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from enum import Enum

class X509ECDSASigningAlgorithms(Enum):
    ecdsa_with_SHA224 = X509DSASignature('ecdsa-with-SHA224',SHA224())
    ecdsa_with_SHA256 = X509DSASignature('ecdsa-with-SHA256', SHA256())
    ecdsa_with_SHA384 = X509DSASignature('ecdsa-with-SHA384', SHA384())
    ecdsa_with_SHA512 = X509DSASignature('ecdsa-with-SHA512', SHA512())


class X509ECDSACertificate(X509Certificate):
    ALG_OID = '1.2.840.10045.2.1'
    PUB_KEY_ENCODER = X509ECDSASubjectPublicKey
    PUB_KEY_DECODER = X509ECDSAPublicKey
    PARAM_ENCODER   = X509ECDSAParams


class X509ECDSACertificateSigningRequest(X509CertificateSigningRequest, X509ECDSACertificate):
    pass
