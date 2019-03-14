from samson.encoding.x509.x509_dsa_public_key import X509DSAPublicKey
from samson.encoding.x509.x509_dsa_subject_public_key import X509DSASubjectPublicKey
from samson.encoding.x509.x509_dsa_params import X509DSAParams
from samson.encoding.x509.x509_certificate import X509Certificate
from pyasn1.type.univ import Integer, SequenceOf
from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256
from pyasn1.codec.der import encoder
from copy import deepcopy


def sign(pki_obj, hash_obj, data):
    new_pki = deepcopy(pki_obj)
    new_pki.hash_obj = hash_obj

    r, s = new_pki.sign(data)
    seq = SequenceOf()
    seq.extend([Integer(r), Integer(s)])

    return Bytes(encoder.encode(seq))


class X509DSACertificate(X509Certificate):
    ALG_OID = '1.2.840.10040.4.1'
    PUB_KEY_ENCODER = X509DSASubjectPublicKey
    PUB_KEY_DECODER = X509DSAPublicKey
    PARAM_ENCODER = X509DSAParams


    SIGNING_ALGS = {
        'id-dsa-with-sha1': lambda pki_obj, data: sign(pki_obj, SHA1(), data),
        'id-dsa-with-sha224': lambda pki_obj, data: sign(pki_obj, SHA224(), data),
        'id-dsa-with-sha256': lambda pki_obj, data: sign(pki_obj, SHA256(), data)
    }


    SIGNING_DEFAULT = 'id-dsa-with-sha256'
