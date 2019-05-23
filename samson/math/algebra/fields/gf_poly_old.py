from samson.encoding.general import int_to_poly, poly_to_int
from samson.math.general import mod_inv
from sympy.polys.domains.field import Field
from sympy.polys.domains.simpledomain import SimpleDomain
from sympy.polys.galoistools import gf_irreducible_p, gf_add, gf_sub, gf_mul, gf_rem, gf_gcdex
from sympy.polys.domains.modularinteger import ModularIntegerFactory
from sympy.abc import x
from sympy import Poly, isprime, ZZ
import itertools


class GFPolyElement(object):
    def __init__(self, poly):
        if type(poly) is int:
            poly = int_to_poly(poly, self.parent.p)

        self.poly = poly


    def rem_and_poly(self, result):
        if self.parent.reducing_poly:
            result = gf_rem(result, self.parent.reducing_poly, self.parent.p, ZZ)
        return self.__class__(Poly(result, x, modulus=self.parent.p))


    def try_coerce(self, other):
        if type(other) is int:
            other = self.rem_and_poly(int_to_poly(other).all_coeffs())
        return other


    def __repr__(self):
        return f"<GFPolyElement: {self.poly}/{self.parent.as_poly}>"

    def __str__(self):
        return self.__repr__()
    

    def __hash__(self):
        return poly_to_int(self.poly) * self.parent.poly_as_int



    def __add__(self, other):
        other = self.try_coerce(other)
        return self.rem_and_poly(gf_add(self.poly.all_coeffs(), other.poly.all_coeffs(), self.parent.p, ZZ))


    def __radd__(self, other):
        return self.__add__(other)


    def __mul__(self, other):
        other = self.try_coerce(other)
        return self.rem_and_poly(gf_mul(self.poly.all_coeffs(), other.poly.all_coeffs(), self.parent.p, ZZ))


    def __rmul__(self, other):
        return self.__mul__(other)


    def __sub__(self, other):
        other = self.try_coerce(other)
        return self.rem_and_poly(gf_sub(self.poly.all_coeffs(), other.poly.all_coeffs(), self.parent.p, ZZ))


    def __rsub__(self, other):
        return self.__sub__(other)
    

    def __invert__(self):
        return self.__class__(Poly(gf_gcdex(self.poly.all_coeffs(), self.parent.reducing_poly, self.parent.p, ZZ)[0], x))


    def __truediv__(self, other):
        other = self.try_coerce(other)
        return self * ~other


    def __floordiv__(self, other):
        return self.__truediv__(other)


    def __mod__(self, other):
        other = self.try_coerce(other)
        return self.rem_and_poly(gf_rem(self.poly.all_coeffs(), other.poly.all_coeffs(), self.parent.p, ZZ))


    def __eq__(self, other):
        other = self.try_coerce(other)
        return self.poly == other.poly and self.parent == other.parent


    def __lt__(self, other):
        other = self.try_coerce(other)
        return poly_to_int(self.poly) < poly_to_int(other.poly)


    def __gt__(self, other):
        other = self.try_coerce(other)
        return poly_to_int(self.poly) > poly_to_int(other.poly)


_gf_poly_cache = {}

def GFPolyFactory(_mod, _n, _reducing_poly, _dom, _parent):
    """Create custom class for specific integer modulus."""
    try:
        _mod = _dom.convert(_mod)
    except Exception:#CoercionFailed:
        ok = False
    else:
        ok = True

    if not ok or _mod < 1:
        raise ValueError("modulus must be a positive integer, got %s" % _mod)

    key = _mod, _n, _reducing_poly, _dom

    try:
        cls = _gf_poly_cache[key]
    except KeyError:
        class cls(GFPolyElement):
            mod, dom = _mod, _dom
            parent = _parent

        cls.__name__ = "PolynomialMod%s" % _mod

        _gf_poly_cache[key] = cls

    return cls


class GFPoly(Field, SimpleDomain):
    def __init__(self, p: int, n: int=1, reducing_poly: Poly=None):
        assert isprime(p)
        self.p = p
        self.n = n


        if reducing_poly:
            reducing_poly = reducing_poly.all_coeffs()
        elif reducing_poly is None:
            if n == 1:
                reducing_poly = Poly(x, x).all_coeffs()
            else:
                for c in itertools.product(range(p), repeat=n):
                    poly = (1, *c)
                    if gf_irreducible_p(poly, p, ZZ):
                        reducing_poly = poly
                        break
        

        dom = ZZ
        self.reducing_poly = reducing_poly
        self.dtype = GFPolyFactory(p, n, reducing_poly, dom, self)
        self.zero  = self.dtype(0)
        self.one   = self.dtype(1)
        self.dom   = dom
        self.mod   = p

        self.poly_as_int = poly_to_int(Poly(self.reducing_poly, x, modulus=self.p)) if self.reducing_poly else 1
        self.as_poly     = Poly(self.reducing_poly, x, modulus=self.p) if self.reducing_poly else None



    def __repr__(self):
        return f"<GFPoly: p={self.p}, n={self.n}, reducing_poly={self.as_poly}>"

    def __str__(self):
        return self.__repr__()
