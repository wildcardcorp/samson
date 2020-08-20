from samson.math.algebra.rings.ring import Ring
from samson.utilities.exceptions import CoercionException
from samson.math.matrix import Matrix

class MatrixRing(Ring):
    """
    Ring of square matrices over a ring.

    Examples:
        >>> from samson.math.all import *
        >>> M = MatrixRing(3, ZZ)
        >>> M.one * 5
        <Matrix: rows=
        [5, 0, 0]
        [0, 5, 0]
        [0, 0, 5]>

    """

    def __init__(self, size: int, ring: Ring):
        """
        Parameters:
            size  (int): Size of matrices.
            ring (Ring): Underlying ring.
        """
        self.size        = size
        self.ring        = ring
        self.order_cache = None

        self.zero = Matrix.fill(self.ring.zero, self.size, coeff_ring=self.ring, ring=self)
        self.one  = Matrix.identity(self.size, coeff_ring=self.ring, ring=self)


    @property
    def characteristic(self) -> int:
        raise NotImplementedError()


    @property
    def order(self) -> int:
        raise NotImplementedError()


    def __repr__(self):
        return f"<MatrixRing: size={self.size}, ring={self.ring}>"


    def shorthand(self) -> str:
        return f'M_{self.size}({self.ring})'


    def coerce(self, other: object) -> Matrix:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            Matrix: Coerced element.
        """
        type_o = type(other)

        if type_o is list:
            elem = Matrix(other, coeff_ring=self.ring, ring=self)

        elif type_o is Matrix:
            elem = other

        else:
            raise CoercionException(self, other)


        assert elem.is_square(), "Elements must be square in a MatrixRing"
        return elem


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.size == other.size


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))
