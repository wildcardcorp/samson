from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_base import PKCS8Base
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import EDCURVE_OID_LOOKUP
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString
from pyasn1.codec.der import encoder, decoder
import math

# https://tools.ietf.org/html/rfc8410
class PKCS8EdDSAPrivateKey(PKCS8Base):
    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 3 and str(items[1][0])[:7] == '1.3.101'
        except Exception as _:
            return False


    @staticmethod
    def encode(eddsa_key: object, **kwargs):
        alg_id = SequenceOf()
        alg_id.setComponentByPosition(0, ObjectIdentifier(eddsa_key.curve.oid))

        zero_fill = math.ceil(eddsa_key.d.int().bit_length() / 8)
        priv_key = OctetString(encoder.encode(OctetString(Bytes.wrap(eddsa_key.d).zfill(zero_fill))))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, priv_key)

        encoded = encoder.encode(top_seq)
        encoded = PKCS8EdDSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.eddsa import EdDSA
        items = bytes_to_der_sequence(buffer)

        curve_oid = str(items[1][0])
        priv_key, _ = decoder.decode(bytes(items[2]))

        d = Bytes(priv_key).int()

        curve = EDCURVE_OID_LOOKUP[curve_oid]
        eddsa = EdDSA(d=d, curve=curve)

        return eddsa
