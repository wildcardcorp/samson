from samson.math.algebra.rings.ring import Ring
from samson.utilities.exceptions import CoercionException
from samson.math.polynomial import Polynomial
from sympy import Expr, Symbol


class PolynomialRing(Ring):
    """
    Ring of polynomials over a ring.

    Examples:
        >>> from samson.math.all import *
        >>> poly_ring = (ZZ/ZZ(53))[x]
        >>> poly_ring(x**3 + 4*x - 3)
        <Polynomial: x**3 + ZZ(4)*x + ZZ(50), coeff_ring=ZZ/ZZ(53)>

    """

    def __init__(self, ring: Ring, symbol: Symbol=None):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring   = ring
        self.symbol = symbol or Symbol('x')


    @property
    def characteristic(self):
        return self.ring.characteristic


    @property
    def order(self) -> int:
        from samson.math.algebra.symbols import oo
        return oo

    def zero(self) -> Polynomial:
        """
        Returns:
            Polynomial: '0' element of the algebra.
        """
        return Polynomial([self.ring.zero()], coeff_ring=self.ring, ring=self, symbol=self.symbol)


    def one(self) -> Polynomial:
        """
        Returns:
            Polynomial: '1' element of the algebra.
        """
        return Polynomial([self.ring.one()], coeff_ring=self.ring, ring=self, symbol=self.symbol)


    def __repr__(self):
        return f"<PolynomialRing ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}[{self.symbol}]'


    def __eq__(self, other: object) -> bool:
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
        if type(other) is int:
            other = [other]

        if type(other) is list or type(other) is dict or issubclass(type(other), Expr):
            return Polynomial(other, coeff_ring=self.ring, ring=self, symbol=self.symbol)

        elif type(other) is Polynomial:
            return other

        raise CoercionException('Coercion failed')


    def element_at(self, x: int) -> Polynomial:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           Polynomial: The `x`-th element.
        """
        base_coeffs = []
        # modulus     = self.ring.characteristic
        modulus     = self.ring.order

        if modulus != 0:
            # Use != to handle negative numbers
            while x != 0 and x != -1:
                x, r = divmod(x, modulus)
                base_coeffs.append(self.ring[r])

            return self(base_coeffs)
        else:
            return self([x])
