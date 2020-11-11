from samson.math.general import is_prime
from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.symbols import Symbol
from samson.math.algebra.rings.ring import left_expression_intercept
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
        self.field = field
        self.val   = self.field.internal_field.coerce(val)


    def __repr__(self):
        return f"<FiniteFieldElement: val={self.val}, field={self.field}>"


    def shorthand(self) -> str:
        return self.field.shorthand() + f'({self.val.shorthand()})'


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return int(self)


    @left_expression_intercept
    def __add__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val + other.val, self.field)


    def __mul__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul

        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val * other.val, self.field)


    @left_expression_intercept
    def __sub__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val - other.val, self.field)


    @left_expression_intercept
    def __mod__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
        other = self.ring.coerce(other)
        return FiniteFieldElement(self.val % other.val, self.field)


    def __invert__(self) -> 'FiniteFieldElement':
        return FiniteFieldElement(~self.val, self.field)


    def __neg__(self) -> 'FiniteFieldElement':
        return FiniteFieldElement(-self.val, self.field)


    @left_expression_intercept
    def __truediv__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
        other = self.ring.coerce(other)
        return self * ~other


    @left_expression_intercept
    def __floordiv__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
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
        <QuotientRing: ring=F_(2**8)[x], quotient=x**7 + x**2 + 1>

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
        x = Symbol(symbol_repr)
        P = self.internal_ring[x]

        if not reducing_poly:
            if n == 1:
                reducing_poly = Polynomial([0, 1], self.internal_ring)
            else:
                max_elem = x**(n+1)
                while True:
                    poly = P.random(max_elem).monic()

                    if poly and poly.is_irreducible():
                        reducing_poly = poly
                        break


        self.reducing_poly  = reducing_poly
        self.internal_field = P/P(reducing_poly)

        self.zero = self.coerce(0)
        self.one  = self.coerce(1)


    def __repr__(self):
        return f"<FiniteField: p={self.p}, n={self.n}, reducing_poly={self.reducing_poly}>"


    def __hash__(self) -> int:
        return hash((self.internal_field, self.reducing_poly, self.__class__))


    def shorthand(self) -> str:
        return f'F_({self.p}**{self.n})' if self.n > 1 else f'F_{self.p}'


    @property
    def characteristic(self) -> int:
        return self.p


    @property
    def order(self) -> int:
        return self.p**self.n


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
        return self(self.internal_field.random(size))


    def __eq__(self, other: 'FiniteField') -> bool:
        return type(self) == type(other) and self.p == other.p and self.n == other.n
