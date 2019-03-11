from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_base import PKCS8Base
from samson.utilities.bytes import Bytes
from samson.utilities.ecc import EDCURVE_OID_LOOKUP
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error
import math

# https://tools.ietf.org/html/rfc8410
class PKCS8EdDSAPrivateKey(PKCS8Base):
    @staticmethod
    def check(buffer: bytes):
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 3 and str(items[1][0])[:7] == '1.3.101'
        except PyAsn1Error as _:
            return False


    @staticmethod
    def encode(eddsa_key: object):
        alg_id = SequenceOf()
        alg_id.setComponentByPosition(0, ObjectIdentifier([int(item) for item in eddsa_key.curve.oid.split('.')]))

        zero_fill = math.ceil(eddsa_key.d.int().bit_length() / 8)
        priv_key = OctetString(encoder.encode(OctetString(Bytes.wrap(eddsa_key.d).zfill(zero_fill))))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, priv_key)

        encoded = encoder.encode(top_seq)
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.eddsa import EdDSA
        items = bytes_to_der_sequence(buffer)

        curve_oid = str(items[1][0])
        priv_key, _ = decoder.decode(bytes(items[2]))

        d = Bytes(priv_key).int()

        curve = EDCURVE_OID_LOOKUP[curve_oid]
        eddsa = EdDSA(d=d, curve=curve)

        return eddsa
