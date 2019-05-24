from samson.math.general import int_to_poly, poly_to_int
from samson.math.general import mod_inv
from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.polynomial_ring import PolynomialRing
from samson.math.algebra.polynomial import Polynomial
from sympy import isprime
from sympy.abc import x
from sympy.polys.galoistools import gf_irreducible_p
import itertools

class FiniteFieldElement(FieldElement):
    def __init__(self, val: Polynomial, field: Field):
        self.field = field
        self.val   = self.field.internal_field.coerce(val)


    def __repr__(self):
        return f"<FiniteFieldElement: val={self.val}, field={self.field}>"

    def __str__(self):
        return self.__repr__()
    

    def shorthand(self) -> str:
        return self.field.shorthand() + f'({self.val.shorthand()})'


    def __add__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val + other.val, self.field)


    def __radd__(self, other: object) -> object:
        return self.__add__(other)

    def __mul__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val * other.val, self.field)

    def __rmul__(self, other: object) -> object:
        return self.__mul__(other)

    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val - other.val, self.field)

    def __rsub__(self, other: object) -> object:
        return self.field.coerce(other) - self
    
    def __mod__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val % other.val, self.field)

    def __invert__(self) -> object:
        return FiniteFieldElement(~self.val, self.field)

    def __neg__(self) -> object:
        return FiniteFieldElement(-self.val, self.field)

    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self * ~other

    def __floordiv__(self, other: object) -> object:
        return self.__truediv__(other)



class FiniteField(Field):
    ELEMENT = FiniteFieldElement

    def __init__(self, p: int, n: int=1, reducing_poly: Polynomial=None):
        from samson.math.algebra.all import ZZ
        from sympy import ZZ as sym_ZZ
        assert isprime(p)
        self.p = p
        self.n = n

        self.internal_ring = ZZ/ZZ(p)

        if not reducing_poly:
            if n == 1:
                reducing_poly = Polynomial([0, 1], self.internal_ring)
            else:
                for c in itertools.product(range(p), repeat=n):
                    poly = (1, *c)
                    if gf_irreducible_p(poly, p, sym_ZZ):
                        reducing_poly = Polynomial(poly[::-1], self.internal_ring)
                        break


        self.reducing_poly  = reducing_poly

        poly_ring           = PolynomialRing(self.internal_ring)
        self.internal_field = poly_ring/poly_ring(reducing_poly)


    def __repr__(self):
        return f"<FiniteField: p={self.p}, n={self.n}, reducing_poly={self.reducing_poly}>"

    def __str__(self):
        return self.__repr__()


    def zero(self) -> FiniteFieldElement:
        return self.coerce(0)


    def one(self) -> FiniteFieldElement:
        return self.coerce(1)


    def shorthand(self) -> str:
        return f'F_({self.p}**{self.n})' if self.n > 1 else f'F_{self.p}'
    

    def coerce(self, other: int) -> object:
        if type(other) is int:
            other = int_to_poly(other, self.p) % self.reducing_poly
        elif type(other) is Polynomial:
            other = other % self.reducing_poly
        
        if not type(other) is FiniteFieldElement:
            other = FiniteFieldElement(self.internal_field(other), self)

        return other


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.p == other.p and self.n == other.n
    

    def __call__(self, element):
        return self.coerce(element)
