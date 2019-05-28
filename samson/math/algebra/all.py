from .fields.finite_field import FiniteField
from.fields.fraction_field import FractionField
from .rings.integers_mod_p import IntegersModP
from .rings.integer_ring import IntegerRing, ZZ
from .rings.polynomial_ring import PolynomialRing
from .rings.quotient_ring import QuotientRing
from .curves.twisted_edwards_curve import TwistedEdwardsCurve
from .curves.weierstrass_curve import WeierstrassCurve
from .polynomial import Polynomial
from .symbols import oo


GF   = FF = FiniteField
QQ   = FractionField(ZZ)
Frac = FractionField