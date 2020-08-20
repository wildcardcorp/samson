from samson.math.algebra.rings.ring import Ring
from samson.utilities.exceptions import CoercionException
from samson.math.polynomial import Polynomial
from samson.math.symbols import Symbol


class PolynomialRing(Ring):
    """
    Ring of polynomials over a ring.

    Examples:
        >>> from samson.math.all import *
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> poly_ring = (ZZ/ZZ(53))[x]
        >>> poly_ring(x**3 + 4*x - 3)
        <Polynomial: x**3 + 4*x + 50, coeff_ring=ZZ/ZZ(53)>

    """

    def __init__(self, ring: Ring, symbol: Symbol=None):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring   = ring
        self.symbol = symbol or Symbol('x')
        self.symbol.build(self)

        self.zero = Polynomial([self.ring.zero], coeff_ring=self.ring, ring=self, symbol=self.symbol)
        self.one  = Polynomial([self.ring.one], coeff_ring=self.ring, ring=self, symbol=self.symbol)


    @property
    def characteristic(self):
        return self.ring.characteristic


    @property
    def order(self) -> int:
        from samson.math.symbols import oo
        return oo


    def __repr__(self):
        return f"<PolynomialRing: ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}[{self.symbol}]'


    def __eq__(self, other: 'PolynomialRing') -> bool:
        return type(self) == type(other) and self.ring == other.ring


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def coerce(self, other: object) -> Polynomial:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            Polynomial: Coerced element.
        """
        from samson.math.sparse_vector import SparseVector

        # Handle grounds
        type_o = type(other)
        if type_o is int or hasattr(other, 'ring') and other.ring == self.ring:
            other  = [other]
            type_o = type(other)

        if type_o is list or type_o is dict or type_o is SparseVector:
            return Polynomial(other, coeff_ring=self.ring, ring=self, symbol=self.symbol)

        elif type_o is Polynomial:
            if other.ring == self:
                return other
            else:
                coeff_coerced = other.change_ring(self.ring)
                coeff_coerced.symbol = self.symbol
                return coeff_coerced

        elif type_o is Symbol and other.var.ring == self:
            return other.var

        raise CoercionException(self, other)


    def element_at(self, x: int) -> Polynomial:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           Polynomial: The `x`-th element.
        """
        base_coeffs = []
        modulus     = self.ring.order

        if modulus != 0:
            # Use != to handle negative numbers
            while x != 0 and x != -1:
                x, r = divmod(x, modulus)
                base_coeffs.append(self.ring[r])

            return self(base_coeffs)
        else:
            return self([x])


    def find_gen(self) -> 'Polynomial':
        """
        Finds a generator of the `Ring`.

        Returns:
            RingElement: A generator element.
        """
        return self.symbol


    def random(self, size: object) -> object:
        """
        Generate a random element.

        Parameters:
            size (int/RingElement): The maximum ordinality/element (non-inclusive).
    
        Returns:
            RingElement: Random element of the algebra.
        """
        if self.characteristic:
            return super().random(size)

        else:
            deg = size.degree()
            max_val = max(size.coeffs.values.values()) + self.ring.one
            return self([self.ring.random(max_val) for _ in range(deg)])


    def interpolate(self, points: list) -> Polynomial:
        """
        Given a list of `points`, returns the polynomial that generates them (i.e. interpolation).

        Parameters:
            points (list): List of points formatted as [(x,y), ...].

        Returns:
            Polynomial: Interpolated polynomial.
        
        Examples:
            >>> from samson.math.all import ZZ, Symbol
            >>> x = Symbol('x')
            >>> P = ZZ[x]
            >>> q = 10*x**8 + 7*x**7 + 25*x**6 + 6*x**5 + 8*x**4 + 9*x**3 + 4*x**2 + 4*x + 3
            >>> P.interpolate([(i, q(i)) for i in range(q.degree()+1)]) == q
            True

        References:
            https://en.wikipedia.org/wiki/Polynomial_interpolation#Constructing_the_interpolation_polynomial
        """
        from samson.utilities.exceptions import NoSolutionException
        from samson.math.algebra.fields.fraction_field import FractionField
        from samson.math.matrix import Matrix

        R = self.ring
        not_field = not R.is_field()

        # Gaussian elimination requires a field
        if not_field:
            R = FractionField(R)
            points = [(R(x), R(y)) for x,y in points]

        # Build the Vandermonde matrix
        degree = len(points)
        a      = Matrix([[p[0] for p in points]], R).T
        vand   = a.apply_elementwise(lambda elem: elem**(degree-1))

        for e in reversed(range(degree-1)):
            vand = vand.row_join(a.apply_elementwise(lambda elem: elem**e))

        # Calculate poly
        y      = Matrix([[p[1] for p in points]], R).T
        result = vand.LUsolve(y).T[0]

        if not_field:
            if not all([c.denominator == self.ring.one for c in result]):
                raise NoSolutionException(f"No solution in ring {self.ring}")

            result = [c.numerator for c in result]

        return self(result[::-1])
