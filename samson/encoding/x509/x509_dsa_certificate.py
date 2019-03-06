from samson.encoding.pkcs1.pkcs1_dsa_public_key import PKCS1DSAPublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error

class X509DSACertificate(object):

    @staticmethod
    def check(buffer: bytes):
        try:
            cert, _ = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
            return str(cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']) == '1.2.840.10040.4.1'
        except PyAsn1Error as _:
            return False


    @staticmethod
    def encode(rsa_key: object):
        pass


    @staticmethod
    def decode(buffer: bytes):
        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
        pub_info = cert['tbsCertificate']['subjectPublicKeyInfo']
        return PKCS1DSAPublicKey.decode(encoder.encode(pub_info))
