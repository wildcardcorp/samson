from pyasn1.type.univ import BitString
import math

class X509EdDSASubjectPublicKey(object):

    @staticmethod
    def encode(eddsa_key: object):
        pub_point = eddsa_key.encode_point(eddsa_key.A)[::-1].int()
        zero_fill = math.ceil(pub_point.bit_length() / 8) * 8
        return BitString(bin(pub_point)[2:].zfill(zero_fill))



    @staticmethod
    def decode(buffer: bytes):
        pass
