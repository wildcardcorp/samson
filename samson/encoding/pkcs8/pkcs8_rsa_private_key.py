from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs1.pkcs1_rsa_private_key import PKCS1RSAPrivateKey
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, Null, OctetString
from pyasn1.codec.der import encoder

class PKCS8RSAPrivateKey(object):
    @staticmethod
    def check(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return len(items) == 3 and str(items[1][0]) == '1.2.840.113549.1.1.1'


    @staticmethod
    def encode(rsa_key: object):
        alg_id = Sequence()
        alg_id.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        alg_id.setComponentByPosition(1, Null())

        param_oct = OctetString(PKCS1RSAPrivateKey.encode(rsa_key))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, param_oct)

        encoded = encoder.encode(top_seq)
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return PKCS1RSAPrivateKey.decode(bytes(items[2]))
