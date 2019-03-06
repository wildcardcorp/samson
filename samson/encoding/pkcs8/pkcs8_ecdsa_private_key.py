from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PublicPoint
from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString
from pyasn1.codec.der import encoder, decoder
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from fastecdsa.point import Point
from fastecdsa.curve import Curve
import math

class PKCS8ECDSAPrivateKey(object):
    @staticmethod
    def check(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return len(items) == 3 and str(items[1][0]) == '1.2.840.10045.2.1'


    @staticmethod
    def encode(ecdsa_key: object):
        alg_id = SequenceOf()
        alg_id.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 10045, 2, 1]))
        alg_id.setComponentByPosition(1, ObjectIdentifier(ber_decoder.decode(b'\x06' + bytes([len(ecdsa_key.G.curve.oid)]) + ecdsa_key.G.curve.oid)[0].asTuple()))

        zero_fill = math.ceil(ecdsa_key.G.curve.q.bit_length() / 8)

        params_seq = Sequence()
        params_seq.setComponentByPosition(0, Integer(1))
        params_seq.setComponentByPosition(1, OctetString(Bytes(ecdsa_key.d).zfill(zero_fill)))
        params_seq.setComponentByPosition(2, PublicPoint(ecdsa_key.format_public_point()))

        param_oct = OctetString(encoder.encode(params_seq))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, param_oct)

        encoded = encoder.encode(top_seq)
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.ecdsa import ECDSA
        items = bytes_to_der_sequence(buffer)

        curve_oid = items[1][1].asTuple()
        params, _ = decoder.decode(bytes(items[2]))

        d = Bytes(params[1]).int()
        x, y = ECDSA.decode_point(Bytes(int(params[2])))

        oid_bytes = ber_encoder.encode(ObjectIdentifier(curve_oid))[2:]
        curve = Curve.get_curve_by_oid(oid_bytes)

        ecdsa = ECDSA(d=d, G=curve.G)
        ecdsa.Q = Point(x, y, curve)

        return ecdsa
