from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_base import PKCS8Base
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PublicPoint
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import WS_OID_LOOKUP
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString
from pyasn1.codec.der import encoder, decoder
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from pyasn1.error import PyAsn1Error
import math

class PKCS8ECDSAPrivateKey(PKCS8Base):

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 3 and str(items[1][0]) == '1.2.840.10045.2.1'
        except PyAsn1Error as _:
            return False



    def encode(self, **kwargs) -> bytes:
        alg_id = SequenceOf()
        alg_id.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 10045, 2, 1]))
        alg_id.setComponentByPosition(1, ObjectIdentifier(ber_decoder.decode(b'\x06' + bytes([len(self.key.G.curve.oid)]) + self.key.G.curve.oid)[0].asTuple()))

        zero_fill = math.ceil(self.key.G.curve.q.bit_length() / 8)

        params_seq = Sequence()
        params_seq.setComponentByPosition(0, Integer(1))
        params_seq.setComponentByPosition(1, OctetString(Bytes(self.key.d).zfill(zero_fill)))
        params_seq.setComponentByPosition(2, PublicPoint(self.key.format_public_point()))

        param_oct = OctetString(encoder.encode(params_seq))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, param_oct)

        encoded = encoder.encode(top_seq)
        encoded = PKCS8ECDSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        items = bytes_to_der_sequence(buffer)

        curve_oid = items[1][1].asTuple()
        params, _ = decoder.decode(bytes(items[2]))

        d = Bytes(params[1]).int()
        x, y = ECDSA.decode_point(Bytes(int(params[2])))

        oid_bytes = ber_encoder.encode(ObjectIdentifier(curve_oid))[2:]
        curve = WS_OID_LOOKUP[oid_bytes]

        ecdsa = ECDSA(d=d, G=curve.G)
        ecdsa.Q = curve(x, y)

        return PKCS8ECDSAPrivateKey(ecdsa)
