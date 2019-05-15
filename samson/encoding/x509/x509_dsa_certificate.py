from samson.encoding.x509.x509_dsa_public_key import X509DSAPublicKey
from samson.encoding.x509.x509_dsa_subject_public_key import X509DSASubjectPublicKey
from samson.encoding.x509.x509_dsa_params import X509DSAParams
from samson.encoding.x509.x509_certificate import X509Certificate
from pyasn1.type.univ import Integer, SequenceOf, BitString
from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256
from pyasn1.codec.der import encoder, decoder
from enum import Enum
from copy import deepcopy


class X509DSASignature(object):
    def __init__(self, name, hash_obj):
        self.name     = name
        self.hash_obj = hash_obj

    def sign(self, pki_obj, data):
        new_pki = deepcopy(pki_obj)
        new_pki.hash_obj = self.hash_obj

        r, s = new_pki.sign(data)
        seq = SequenceOf()
        seq.extend([Integer(r), Integer(s)])
        return BitString(Bytes(encoder.encode(seq)).int())


    def verify(self, pki_obj, data, sig):
        decoded, _ = decoder.decode(Bytes(int(sig)))
        sig = [int(item) for item in decoded]

        new_pki = deepcopy(pki_obj)
        new_pki.hash_obj = self.hash_obj
        return pki_obj.verify(data, sig)


class X509DSASigningAlgorithms(Enum):
    id_dsa_with_sha1   = X509DSASignature('id-dsa-with-sha1', SHA1())
    id_dsa_with_sha224 = X509DSASignature('id-dsa-with-sha224', SHA224())
    id_dsa_with_sha256 = X509DSASignature('id-dsa-with-sha256', SHA256())


class X509DSACertificate(X509Certificate):
    ALG_OID = '1.2.840.10040.4.1'
    PUB_KEY_ENCODER = X509DSASubjectPublicKey
    PUB_KEY_DECODER = X509DSAPublicKey
    PARAM_ENCODER   = X509DSAParams
