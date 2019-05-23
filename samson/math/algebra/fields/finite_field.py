from samson.encoding.general import int_to_poly, poly_to_int
from samson.math.general import mod_inv
from samson.math.algebra.fields.field import Field, FieldElement
from sympy import Poly, isprime, ZZ, Symbol
from sympy.abc import x
from sympy.polys.galoistools import gf_irreducible_p, gf_add, gf_sub, gf_mul, gf_rem, gf_gcdex
import itertools

class FiniteFieldElement(FieldElement):
    def __init__(self, val: Poly, field: Field):
        self.field = field

        is_symbol = type(val) is Symbol

        if type(val) is Poly:
            val = poly_to_int(val, self.field.p)

        val %= self.field.p ** self.field.n

        if is_symbol:
            val = [val]
        else:
            val = int_to_poly(val, self.field.p).all_coeffs()

        self.val = Poly(gf_rem(val, self.field.reducing_poly, self.field.p, ZZ), x, modulus=self.field.p)


    def rem_and_poly(self, result: list) -> object:
        if self.field.reducing_poly:
            result = gf_rem(result, self.field.reducing_poly, self.field.p, ZZ)
        return FiniteFieldElement(Poly(result, x, modulus=self.field.p), self.field)


    def coerce(self, other: int) -> object:
        if type(other) is int:
            other = self.rem_and_poly(int_to_poly(other, self.field.p).all_coeffs())
        return other


    def __repr__(self):
        return f"<FiniteFieldElement: val={self.val}, field={self.field}>"

    def __str__(self):
        return self.__repr__()
    

    def shorthand(self) -> str:
        return self.field.shorthand() + f'({poly_to_int(self.val, self.field.p)})'


    def __add__(self, other: object) -> object:
        other = self.coerce(other)
        return self.rem_and_poly(gf_add(self.val.all_coeffs(), other.val.all_coeffs(), self.field.p, ZZ))

    def __radd__(self, other: object) -> object:
        return self.__add__(other)

    def __mul__(self, other: object) -> object:
        other = self.coerce(other)
        return self.rem_and_poly(gf_mul(self.val.all_coeffs(), other.val.all_coeffs(), self.field.p, ZZ))

    def __rmul__(self, other: object) -> object:
        return self.__mul__(other)

    def __sub__(self, other: object) -> object:
        other = self.coerce(other)
        return self.rem_and_poly(gf_sub(self.val.all_coeffs(), other.val.all_coeffs(), self.field.p, ZZ))

    def __rsub__(self, other: object) -> object:
        return self.__sub__(other)
    
    def __mod__(self, other: object) -> object:
        other = self.coerce(other)
        return self.rem_and_poly(gf_rem(self.val.all_coeffs(), other.val.all_coeffs(), self.field.p, ZZ))

    def __invert__(self) -> object:
        return FiniteFieldElement(Poly(gf_gcdex(self.val.all_coeffs(), self.field.reducing_poly, self.field.p, ZZ)[0], x), self.field)

    def __neg__(self) -> object:
        return FiniteFieldElement(-poly_to_int(self.val, self.field.p), self.field)

    def __truediv__(self, other: object) -> object:
        other = self.coerce(other)
        return self * ~other

    def __floordiv__(self, other: object) -> object:
        return self.__truediv__(other)


class FiniteField(Field):
    ELEMENT = FiniteFieldElement

    def __init__(self, p: int, n: int=1, reducing_poly: Poly=None):
        assert isprime(p)
        self.p = p
        self.n = n

        if reducing_poly:
            reducing_poly = reducing_poly.all_coeffs()
        else:
            if n == 1:
                reducing_poly = Poly(x, x).all_coeffs()
            else:
                for c in itertools.product(range(p), repeat=n):
                    poly = (1, *c)
                    if gf_irreducible_p(poly, p, ZZ):
                        reducing_poly = poly
                        break
        

        self.reducing_poly = reducing_poly


    def __repr__(self):
        return f"<FiniteField: p={self.p}, n={self.n}, reducing_poly={Poly(self.reducing_poly, x, modulus=self.p)}>"

    def __str__(self):
        return self.__repr__()


    def zero(self) -> FiniteFieldElement:
        return FiniteFieldElement(0, self)

    def one(self) -> FiniteFieldElement:
        return FiniteFieldElement(1, self)


    def shorthand(self) -> str:
        return f'F_({self.p}**{self.n})' if self.n > 1 else f'F_{self.p}'
    

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.p == other.p and self.n == other.n
    

    def __getitem__(self, x: int):
        from samson.math.algebra.rings.polynomial_ring import PolynomialRing
        return PolynomialRing(self)