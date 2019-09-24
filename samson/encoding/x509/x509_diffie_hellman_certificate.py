from samson.encoding.x509.x509_diffie_hellman_public_key import X509DiffieHellmanPublicKey
from samson.encoding.x509.x509_diffie_hellman_subject_public_key import X509DiffieHellmanSubjectPublicKey
from samson.encoding.x509.x509_diffie_hellman_params import X509DiffieHellmanParams
from samson.encoding.x509.x509_certificate import X509Certificate

class X509DiffieHellmanCertificate(X509Certificate):
    ALG_OID = '1.2.840.113549.1.3.1'
    PUB_KEY_ENCODER = X509DiffieHellmanSubjectPublicKey
    PUB_KEY_DECODER = X509DiffieHellmanPublicKey
    PARAM_ENCODER   = X509DiffieHellmanParams
