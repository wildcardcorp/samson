from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.polynomial import Polynomial
from sympy import Expr

class PolynomialElement(RingElement):
    """
    Element of a `PolynomialRing`.
    """

    def __init__(self, val: Polynomial, ring: Ring):
        """
        Parameters:
            val (Polynomial): Value of the element.
            ring      (Ring): Parent ring.
        """
        self.val  = val
        self.ring = ring


    def __repr__(self):
        return f"<PolynomialElement val={self.val}, ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}({self.val.shorthand()})'


    def __add__(self, other: object) -> object:
        return PolynomialElement(self.val + other.val, self.ring)


    def __sub__(self, other: object) -> object:
        return PolynomialElement(self.val - other.val, self.ring)


    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return super().__mul__(other)

        return PolynomialElement(self.val * other.val, self.ring)


    def __truediv__(self, other: object) -> object:
        return PolynomialElement(self.val / other.val, self.ring)


    __floordiv__ = __truediv__


    def __mod__(self, other: object) -> object:
        return PolynomialElement(self.val % other.val, self.ring)


    def __neg__(self) -> object:
        return PolynomialElement(-self.val, self.ring)



class PolynomialRing(Ring):
    """
    Ring of polynomials over a ring.

    Examples:
        >>> from samson.math.all import *
        >>> poly_ring = (ZZ/ZZ(53))[x]
        >>> poly_ring(x**3 + 4*x - 3)
        <PolynomialElement val=<Polynomial: x**3 + ZZ(4)*x + ZZ(50), ring=ZZ/ZZ(53)>, ring=ZZ/ZZ(53)[x]>

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


    def zero(self) -> PolynomialElement:
        """
        Returns:
            PolynomialElement: '0' element of the algebra.
        """
        return PolynomialElement(Polynomial([self.ring(0)], self.ring), self)


    def one(self) -> PolynomialElement:
        """
        Returns:
            PolynomialElement: '1' element of the algebra.
        """
        return PolynomialElement(Polynomial([self.ring(1)], self.ring), self)


    def random(self, size: int=None) -> PolynomialElement:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            PolynomialElement: Random element of the algebra.
        """
        if not size:
            size = 1

        return PolynomialElement(Polynomial([self.ring.random() for _ in range(size)], self.ring), self)


    def __repr__(self):
        return f"<PolynomialRing ring={self.ring}>"


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}[x]'


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def coerce(self, other: object) -> PolynomialElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            PolynomialElement: Coerced element.
        """
        if type(other) is list or issubclass(type(other), Expr):
            return PolynomialElement(Polynomial(other, self.ring), self)

        elif type(other) is Polynomial:
            return PolynomialElement(other, self)

        elif type(other) is PolynomialElement:
            return other

        raise Exception('Coercion failed')
