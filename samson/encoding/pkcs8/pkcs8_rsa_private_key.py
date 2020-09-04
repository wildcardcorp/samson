from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_base import PKCS8Base
from samson.encoding.pkcs1.pkcs1_rsa_private_key import PKCS1RSAPrivateKey
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, Null, OctetString
from pyasn1.codec.der import encoder

class PKCS8RSAPrivateKey(PKCS8Base):
    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 3 and str(items[1][0]) == '1.2.840.113549.1.1.1'
        except Exception as _:
            return False



    def encode(self, **kwargs) -> bytes:
        alg_id = Sequence()
        alg_id.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        alg_id.setComponentByPosition(1, Null())

        param_oct = OctetString(PKCS1RSAPrivateKey(self.key).encode(encode_pem=False))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, param_oct)

        encoded = encoder.encode(top_seq)
        encoded = PKCS8RSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        items = bytes_to_der_sequence(buffer)
        return PKCS8RSAPrivateKey(PKCS1RSAPrivateKey.decode(bytes(items[2])).key)
