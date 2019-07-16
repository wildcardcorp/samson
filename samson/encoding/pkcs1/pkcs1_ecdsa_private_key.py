from samson.encoding.general import export_der, bytes_to_der_sequence
from pyasn1.type.univ import Integer, OctetString, ObjectIdentifier, BitString, tag
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from samson.encoding.pem import PEMEncodable
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import WS_OID_LOOKUP
import math

def parse_ec_params(items, curve_idx, pub_point_idx):
    from samson.public_key.ecdsa import ECDSA

    curve_oid = items[curve_idx].asTuple()
    oid_bytes = ber_encoder.encode(ObjectIdentifier(curve_oid))[2:]
    curve = WS_OID_LOOKUP[oid_bytes]

    x_y_bytes = Bytes(int(items[pub_point_idx]))
    x, y = ECDSA.decode_point(x_y_bytes)

    return x, y, curve


class NamedCurve(ObjectIdentifier):
    tagSet = baseTagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 6)
    ).tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

    typeId = ObjectIdentifier.typeId



class PublicPoint(BitString):
    tagSet = baseTagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 3)
    ).tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))

    typeId = BitString.typeId



class PKCS1ECDSAPrivateKey(PEMEncodable):
    """
    Not in the RFC spec, but OpenSSL supports it.
    """

    DEFAULT_MARKER = 'EC PRIVATE KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 4 and int(items[0]) == 1
        except Exception as _:
            return False


    @staticmethod
    def encode(ecdsa_key: object, **kwargs):
        zero_fill = math.ceil(ecdsa_key.G.curve.q.bit_length() / 8)
        encoded = export_der([1, Bytes(ecdsa_key.d).zfill(zero_fill), ber_decoder.decode(b'\x06' + bytes([len(ecdsa_key.G.curve.oid)]) + ecdsa_key.G.curve.oid)[0].asTuple(), ecdsa_key.format_public_point()], item_types=[Integer, OctetString, NamedCurve, PublicPoint])
        encoded = PKCS1ECDSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.ecdsa import ECDSA
        items = bytes_to_der_sequence(buffer)

        d = Bytes(items[1]).int()

        x, y, curve = parse_ec_params(items, 2, 3)
        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = curve(x, y)

        return ecdsa
