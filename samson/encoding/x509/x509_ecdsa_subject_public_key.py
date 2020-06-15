from pyasn1.type.univ import BitString

class X509ECDSASubjectPublicKey(object):

    @staticmethod
    def encode(ecdsa_key: 'ECDSA') -> BitString:
        return BitString(ecdsa_key.format_public_point())


    @staticmethod
    def decode(buffer: bytes) -> 'ECDSA':
        pass
