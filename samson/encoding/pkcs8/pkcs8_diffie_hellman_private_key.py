from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_base import PKCS8Base
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString
from pyasn1.codec.der import decoder, encoder

class PKCS8DiffieHellmanPrivateKey(PKCS8Base):

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 3 and str(items[1][0]) == '1.2.840.113549.1.3.1'
        except Exception as _:
            return False



    def encode(self, **kwargs) -> bytes:
        dh_params = SequenceOf()
        dh_params.setComponentByPosition(0, Integer(self.key.p))
        dh_params.setComponentByPosition(1, Integer(self.key.g))

        alg_id = Sequence()
        alg_id.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 113549, 1, 3, 1]))
        alg_id.setComponentByPosition(1, dh_params)

        param_oct = OctetString(encoder.encode(Integer(self.key.key)))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, param_oct)

        encoded = encoder.encode(top_seq)
        encoded = PKCS8DiffieHellmanPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'DiffieHellman':
        from samson.protocols.diffie_hellman import DiffieHellman
        items = bytes_to_der_sequence(buffer)

        p, g   = [int(item) for item in items[1][1]]
        key, _ = decoder.decode(bytes(items[2]))
        key    = int(key)
        dh     = DiffieHellman(p=p, g=g, key=key)

        return PKCS8DiffieHellmanPrivateKey(dh)
