from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve
from samson.math.algebra.rings.integer_ring import ZZ
from pyasn1.codec.der import decoder
from pyasn1.type.univ import Sequence
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error

class X509ECDSAExplicitCertificate(object):

    @staticmethod
    def check(buffer: bytes):
        try:
            cert, _ = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
            alg = cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
            return str(alg['algorithm']) == '1.2.840.10045.2.1' and type(decoder.decode(alg['parameters'])[0]) == Sequence
        except PyAsn1Error as _:
            return False


    @staticmethod
    def encode(ecdsa_key: 'ECDSA') -> 'X509ECDSAExplicitCertificate':
        pass


    @staticmethod
    def decode(buffer: bytes) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA

        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
        pub_info = cert['tbsCertificate']['subjectPublicKeyInfo']

        curve_params, _ = decoder.decode(Bytes(pub_info['algorithm']['parameters']))

        p = int(curve_params[1][1])
        b = Bytes(curve_params[2][1]).int()
        q = int(curve_params[4])
        gx, gy = ECDSA.decode_point(Bytes(curve_params[3]))

        curve = WeierstrassCurve(a=-3, b=b, ring=ZZ/ZZ(p), cardinality=q, base_tuple=(gx, gy))

        x, y = ECDSA.decode_point(Bytes(int(pub_info['subjectPublicKey'])))
        ecdsa = ECDSA(curve.G, None, d=1)
        ecdsa.Q = curve(x, y)

        return ecdsa
