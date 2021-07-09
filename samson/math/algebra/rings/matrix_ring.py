from samson.math.algebra.rings.ring import Ring
from samson.utilities.exceptions import CoercionException, NoSolutionException
from samson.math.matrix import Matrix

class MatrixRing(Ring):
    """
    Ring of square matrices over a ring.

    Examples:
        >>> from samson.math.all import *
        >>> M = MatrixRing(ZZ, 3)
        >>> M.one * 5
        <Matrix: coeff_ring=ZZ, num_rows=3, num_cols=3, 
           0  1  2
        0 [5, 0, 0]
        1 [0, 5, 0]
        2 [0, 0, 5]>


    """

    def __init__(self, ring: Ring, size: int):
        """
        Parameters:
            ring (Ring): Underlying ring.
            size  (int): Size of matrices.
        """
        self.ring        = ring
        self.size        = size
        self.order_cache = None

        self.zero = Matrix.fill(self.ring.zero, self.size, coeff_ring=self.ring, ring=self)
        self.one  = Matrix.identity(self.size, coeff_ring=self.ring, ring=self)


    def characteristic(self) -> int:
        raise NotImplementedError()


    def order(self) -> int:
        raise NotImplementedError()



    def __reprdir__(self):
        return ['size', 'ring']


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


        if not elem.is_square():
            raise CoercionException(elem, "Elements must be square in a MatrixRing")

        return elem


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.ring == other.ring and self.size == other.size


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__, self.size))


    def random(self, size: object=None) -> 'RingElement':
        """
        Generate a random element.

        Parameters:
            size (int/RingElement): The maximum ordinality/element (non-inclusive).

        Returns:
            RingElement: Random element of the algebra.
        """
        return Matrix([[self.ring.random(size) for _ in range(self.size)] for _ in range(self.size)])



    def dft(self, w: 'RingElement'=None, unitary: bool=False) -> 'Matrix':
        if not w:
            roots = self.ring.one.kth_root(self.size, return_all=True)
            non_trivial = [r for r in roots if r != self.ring.one]

            if not non_trivial:
                raise NoSolutionException(f'{self.ring} does not have a non-trivial {self.size}-th root of unity')

            w = non_trivial[0]

        dft = Matrix([[w**(i*j) for j in range(self.size)] for i in range(self.size)])

        if unitary:
            dft /= self.ring(self.size).sqrt()

        return dft
