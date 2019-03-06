from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PKCS1ECDSAPrivateKey, parse_ec_params
from pyasn1.type.univ import ObjectIdentifier, BitString, SequenceOf
from pyasn1.codec.ber import decoder as ber_decoder
from fastecdsa.point import Point

class X509ECDSAPublicKey(object):

    @staticmethod
    def check(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return not PKCS1ECDSAPrivateKey.check(buffer) and len(items) == 2 and str(items[0][0]) == '1.2.840.10045.2.1'


    @staticmethod
    def encode(dsa_key: object):
        curve_seq = [ObjectIdentifier([1, 2, 840, 10045, 2, 1]), ObjectIdentifier(ber_decoder.decode(b'\x06' + bytes([len(dsa_key.G.curve.oid)]) + dsa_key.G.curve.oid)[0].asTuple())]
        encoded = export_der([curve_seq, dsa_key.format_public_point()], item_types=[SequenceOf, BitString])
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.ecdsa import ECDSA
        items = bytes_to_der_sequence(buffer)

        # Move up OID for convenience
        items[0] = items[0][1]
        d = 1

        Q = Point(*parse_ec_params(items, 0, 1))
        ecdsa = ECDSA(G=Q.curve.G, hash_obj=None, d=d)
        ecdsa.Q = Q

        return ecdsa
