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
        <Polynomial: x**3 + ZZ(4)*x + ZZ(50), coeff_ring=ZZ/ZZ(53)>

    """

    def __init__(self, ring: Ring, symbol: Symbol=None):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring   = ring
        self.symbol = symbol or Symbol('x')
        self.symbol.build(self)


    @property
    def characteristic(self):
        return self.ring.characteristic


    @property
    def order(self) -> int:
        from samson.math.symbols import oo
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
        return f"<PolynomialRing: ring={self.ring}>"


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
        # Handle grounds
        type_o = type(other)
        if type_o is int or hasattr(other, 'ring') and other.ring == self.ring:
            other  = [other]
            type_o = type(other)

        if type_o is list or type_o is dict:
            return Polynomial(other, coeff_ring=self.ring, ring=self, symbol=self.symbol)

        elif type_o is Polynomial and other.ring == self:
            return other

        elif type_o is Symbol and other.var.ring == self:
            return other.var

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
        modulus     = self.ring.order

        if modulus != 0:
            # Use != to handle negative numbers
            while x != 0 and x != -1:
                x, r = divmod(x, modulus)
                base_coeffs.append(self.ring[r])

            return self(base_coeffs)
        else:
            return self([x])
