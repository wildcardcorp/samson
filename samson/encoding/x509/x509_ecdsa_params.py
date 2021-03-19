from pyasn1.type.univ import ObjectIdentifier, Sequence, Integer, OctetString
from pyasn1.codec.ber import decoder as ber_decoder
from samson.utilities.bytes import Bytes
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import parse_ec_params

class X509ECDSAParams(object):

    @staticmethod
    def encode(ecdsa_key):
        E = ecdsa_key.G.curve
        if hasattr(E, 'oid') and E.oid:
            return ObjectIdentifier(ber_decoder.decode(b'\x06' + bytes([len(E.oid)]) + E.oid)[0].asTuple())

        else:
            # X9.62 explicit params
            # https://www.itu.int/wftp3/Public/t/fl/itu-t/x/x894/2018-cor1/ANSI-X9-62.html
            from samson.public_key.ecdsa import ECDSA
            dummy = ECDSA(ecdsa_key.G, d=1)

            prime_seq = Sequence()
            prime_seq.setComponentByPosition(0, ObjectIdentifier('1.2.840.10045.1.1'))
            prime_seq.setComponentByPosition(1, Integer(E.p))
            
            curve_seq = Sequence()
            curve_seq.setComponentByPosition(0, OctetString(Bytes(int(E.a))))
            curve_seq.setComponentByPosition(1, OctetString(Bytes(int(E.b))))


            top_seq = Sequence()
            top_seq.setComponentByPosition(0, Integer(1))
            top_seq.setComponentByPosition(1, prime_seq)
            top_seq.setComponentByPosition(2, curve_seq)
            top_seq.setComponentByPosition(3, OctetString(Bytes(int(dummy.format_public_point(), 2))))
            top_seq.setComponentByPosition(4, Integer(ecdsa_key.G.order()))
            top_seq.setComponentByPosition(5, Integer(E.order() // ecdsa_key.G.order()))
            return top_seq



    @staticmethod
    def decode(curve_spec, pub_params):
        from samson.public_key.ecdsa import ECDSA
        try:
            x, y, curve = parse_ec_params([curve_spec, pub_params], 0, 1)

        # If we're here, it's probably using explicit parameters
        except Exception:
            from samson.math.algebra.rings.integer_ring import ZZ
            from samson.math.algebra.curves.weierstrass_curve import EllipticCurve

            _version, prime_params, curve_params, encoded_base, g_order, cofactor = [curve_spec[i] for i in range(len(curve_spec))]

            p        = int(prime_params[1])
            a, b     = Bytes(curve_params[0]).int(), Bytes(curve_params[1]).int()
            gx, gy   = ECDSA.decode_point(Bytes(encoded_base))
            g_order  = int(g_order)
            cofactor = int(cofactor)

            R     = ZZ/ZZ(p)
            curve = EllipticCurve(R(a), R(b), cardinality=cofactor*g_order, base_tuple=(gx, gy))
            x, y  = ECDSA.decode_point(Bytes(int(pub_params)))


        ecdsa   = ECDSA(G=curve.G, hash_obj=None, d=1)
        ecdsa.d = None
        ecdsa.Q = curve(x, y)

        return ecdsa
