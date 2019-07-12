from samson.math.algebra.curves.twisted_edwards_curve import EdwardsCurve25519, EdwardsCurve448
from samson.math.algebra.curves.montgomery_curve import Curve25519, Curve448
from enum import Enum

EDCURVE_OID_LOOKUP = {
    Curve25519.oid: Curve25519,
    Curve448.oid: Curve448,
    EdwardsCurve25519.oid: EdwardsCurve25519,
    EdwardsCurve448.oid: EdwardsCurve448,
}


class EllipticCurveCardAlg(Enum):
    AUTO    = 0
    BSGS    = 1
    SCHOOFS = 2
