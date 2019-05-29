from samson.math.algebra.curves.twisted_edwards_curve import EdwardsCurve25519, EdwardsCurve448
from samson.math.algebra.curves.montgomery_curve import Curve25519, Curve448
from fastecdsa.curve import P192, P224, P256, P384, P521
from enum import Enum

EDCURVE_OID_LOOKUP = {
    Curve25519.oid: Curve25519,
    Curve448.oid: Curve448,
    EdwardsCurve25519.oid: EdwardsCurve25519,
    EdwardsCurve448.oid: EdwardsCurve448,
}

# Convenience aliases
secp192r1 = P192
secp224r1 = P224
secp256r1 = P256
secp384r1 = P384
secp521r1 = P521


class EllipticCurveCardAlg:
    AUTO    = 0
    BSGS    = 1
    SCHOOFS = 2