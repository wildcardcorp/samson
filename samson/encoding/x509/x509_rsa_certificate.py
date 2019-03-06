from samson.utilities.bytes import Bytes
from samson.encoding.pkcs1.pkcs1_rsa_public_key import PKCS1RSAPublicKey
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error

class X509RSACertificate(object):

    @staticmethod
    def check(buffer: bytes):
        try:
            cert, _ = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
            return str(cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']) == '1.2.840.113549.1.1.1'
        except PyAsn1Error as _:
            return False


    @staticmethod
    def encode(rsa_key: object):
        pass


    @staticmethod
    def decode(buffer: bytes):
        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
        buffer = Bytes(int(cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']))
        return PKCS1RSAPublicKey.decode(buffer)
