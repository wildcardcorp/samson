from .rings.integers_mod_p import IntegersModP
from .rings.integer_ring import IntegerRing
from .rings.polynomial_ring import PolynomialRing
from .rings.quotient_ring import QuotientRing
from .fields.finite_field import FiniteField
from .polynomial import Polynomial

GF = FF = FiniteField
ZZ = IntegerRing()