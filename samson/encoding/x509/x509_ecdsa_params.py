from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.ber import decoder as ber_decoder

class X509ECDSAParams(object):

    @staticmethod
    def encode(ecdsa_key):
        return ObjectIdentifier(ber_decoder.decode(b'\x06' + bytes([len(ecdsa_key.G.curve.oid)]) + ecdsa_key.G.curve.oid)[0].asTuple())
