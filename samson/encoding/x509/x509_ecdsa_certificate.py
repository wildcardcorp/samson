from samson.utilities.bytes import Bytes
from samson.encoding.x509.x509_ecdsa_public_key import X509ECDSAPublicKey
from samson.encoding.x509.x509_certificate import X509Certificate
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error
from fastecdsa.curve import Curve
from fastecdsa.point import Point

class X509ECDSACertificate(X509Certificate):
    ALG_OID = '1.2.840.10045.2.1'
    PUB_KEY_ENCODER = X509RSAParams
    PUB_KEY_DECODER = X509ECDSAPublicKey

    # @staticmethod
    # def check(buffer: bytes):
    #     try:
    #         cert, _ = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
    #         alg = cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
    #         return str(alg['algorithm']) == '1.2.840.10045.2.1' and type(decoder.decode(alg['parameters'])[0]) == ObjectIdentifier
    #     except PyAsn1Error as _:
    #         return False


    # @staticmethod
    # def encode(rsa_key: object):
    #     pass


    # @staticmethod
    # def decode(buffer: bytes):
    #     cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
    #     pub_info = cert['tbsCertificate']['subjectPublicKeyInfo']
    #     return X509ECDSAPublicKey.decode(encoder.encode(pub_info))
