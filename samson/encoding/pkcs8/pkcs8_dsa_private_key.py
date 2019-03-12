from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_base import PKCS8Base
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString
from pyasn1.codec.der import decoder, encoder

class PKCS8DSAPrivateKey(PKCS8Base):

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 3 and str(items[1][0]) == '1.2.840.10040.4.1'
        except Exception as _:
            return False


    @staticmethod
    def encode(dsa_key: object, **kwargs):
        dss_params = SequenceOf()
        dss_params.setComponentByPosition(0, Integer(dsa_key.p))
        dss_params.setComponentByPosition(1, Integer(dsa_key.q))
        dss_params.setComponentByPosition(2, Integer(dsa_key.g))

        alg_id = Sequence()
        alg_id.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 10040, 4, 1]))
        alg_id.setComponentByPosition(1, dss_params)

        param_oct = OctetString(encoder.encode(Integer(dsa_key.x)))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, param_oct)

        encoded = encoder.encode(top_seq)
        encoded = PKCS8DSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.dsa import DSA
        items = bytes_to_der_sequence(buffer)

        p, q, g = [int(item) for item in items[1][1]]
        x, _ = decoder.decode(bytes(items[2]))
        x = int(x)
        dsa = DSA(None, p=p, q=q, g=g, x=x)

        return dsa
