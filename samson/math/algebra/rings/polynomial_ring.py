from samson.math.algebra.rings.ring import Ring
from samson.utilities.exceptions import CoercionException
from samson.math.polynomial import Polynomial
from sympy import Expr


class PolynomialRing(Ring):
    """
    Ring of polynomials over a ring.

    Examples:
        >>> from samson.math.all import *
        >>> poly_ring = (ZZ/ZZ(53))[x]
        >>> poly_ring(x**3 + 4*x - 3)
        <Polynomial: x**3 + ZZ(4)*x + ZZ(50), coeff_ring=ZZ/ZZ(53)>

    """

    def __init__(self, ring: Ring):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring = ring


    @property
    def characteristic(self):
        return self.ring.characteristic


    def zero(self) -> Polynomial:
        """
        Returns:
            Polynomial: '0' element of the algebra.
        """
        return Polynomial([self.ring(0)], coeff_ring=self.ring, ring=self)


    def one(self) -> Polynomial:
        """
        Returns:
            Polynomial: '1' element of the algebra.
        """
        return Polynomial([self.ring(1)], coeff_ring=self.ring, ring=self)


    def __repr__(self):
        return f"<PolynomialRing ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}[x]'


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

        if type(other) is list or issubclass(type(other), Expr):
            return Polynomial(other, coeff_ring=self.ring, ring=self)

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
        modulus     = self.ring.characteristic

        if modulus != 0:
            # Use != to handle negative numbers
            while x != 0 and x != -1:
                x, r = divmod(x, modulus)
                base_coeffs.append(self.ring[r])

            return self(base_coeffs)
        else:
            return self([x])
