from pyasn1.type.univ import BitString

class X509ECDSASubjectPublicKey(object):

    @staticmethod
    def encode(ecdsa_key: object):
        return BitString(ecdsa_key.format_public_point())


    @staticmethod
    def decode(buffer: bytes):
        pass
