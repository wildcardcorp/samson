from samson.math.general import is_prime
from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.symbols import Symbol
from samson.math.polynomial import Polynomial

class FiniteFieldElement(FieldElement):
    """
    Element of a `FiniteField`.
    """

    def __init__(self, val: Polynomial, field: Field):
        """
        Parameters:
            val    (Polynomial): Value of the element.
            field (FiniteField): Parent field.
        """
        self.val = field.internal_field.coerce(val)
        super().__init__(field)


    def shorthand(self) -> str:
        return self.field.shorthand() + f'({self.val.shorthand()})'


    def __call__(self, arg):
        return self.val(arg)
    

    def __iter__(self):
        return self.val.val.__iter__()


    def __getitem__(self, idx):
        return self.val.val[idx]


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return int(self)


    def __invert__(self) -> 'FiniteFieldElement':
        return FiniteFieldElement(~self.val, self.field)


    def __neg__(self) -> 'FiniteFieldElement':
        return FiniteFieldElement(-self.val, self.field)


    def __elemfloordiv__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
        return self.__truediv__(other)


class FiniteField(Field):
    """
    Finite field of GF(p**n) constructed using a `PolynomialRing`.

    Examples:
        >>> from samson.math import *
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> F = FiniteField(2, 8)
        >>> assert F[5] / F[5] == F(1)
        >>> F[x]/(x**7 + x**2 + 1)
        <QuotientRing: ring=F_(2^8)[x], quotient=x^7 + x^2 + 1>

    """

    def __init__(self, p: int, n: int=1, reducing_poly: Polynomial=None, symbol_repr: str='x'):
        """
        Parameters:
            p                    (int): Prime.
            n                    (int): Exponent.
            reducing_poly (Polynomial): Polynomial to reduce the `PolynomialRing`.
        """
        from samson.math.algebra.rings.integer_ring import ZZ

        assert is_prime(p)
        self.p = p
        self.n = n

        self.internal_ring = ZZ/ZZ(p)

        if reducing_poly:
            assert reducing_poly.coeff_ring == self.internal_ring
            x = reducing_poly.symbol
            P = self.internal_ring[x]

        else:
            x = Symbol(symbol_repr)
            P = self.internal_ring[x]

            if n == 1:
                reducing_poly = Polynomial([0, 1], self.internal_ring)

            elif p == 2:
                from samson.auxiliary.gf2_irreducible_poly_db import build_gf2_irreducible_poly
                reducing_poly = build_gf2_irreducible_poly(P, n)

            else:
                reducing_poly = P.find_irreducible_poly(n)


        self.reducing_poly   = reducing_poly
        self.internal_field  = P/P(reducing_poly)
        if n > 1:
            self.internal_field.quotient.cache_div((n-1)*2)

        self.symbol          = x
        self.symbol.top_ring = self

        self.zero = self.coerce(0)
        self.one  = self.coerce(1)
        super().__init__()


    def __reprdir__(self):
        return ['p', 'n', 'reducing_poly',]


    def __hash__(self) -> int:
        return hash((self.internal_field, self.reducing_poly, self.__class__))


    def shorthand(self) -> str:
        return f'F_({self.p}^{self.n})' if self.n > 1 else f'F_{self.p}'


    def characteristic(self) -> int:
        return self.p


    def order(self) -> int:
        return self.p**self.n


    def is_superstructure_of(self, R: 'Ring') -> bool:
        """
        Determines whether `self` is a superstructure of `R`.

        Parameters:
            R (Ring): Possible substructure.

        Returns:
            bool: Whether `self` is a superstructure of `R`.
        """
        return self.internal_field.is_superstructure_of(R)


    def coerce(self, other: object) -> FiniteFieldElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            FiniteFieldElement: Coerced element.
        """
        if not type(other) is FiniteFieldElement:
            other = FiniteFieldElement(self.internal_field(other), self)

        return other


    def element_at(self, x: int) -> FiniteFieldElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           FiniteFieldElement: The `x`-th element.
        """
        return FiniteFieldElement(self.internal_field.element_at(x), self)


    def random(self, size: FiniteFieldElement=None) -> FiniteFieldElement:
        if size is not None:
            size = size.val
        return self(self.internal_field.random(size))


    def __eq__(self, other: 'FiniteField') -> bool:
        return type(self) == type(other) and self.p == other.p and self.n == other.n
