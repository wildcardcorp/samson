from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import gaussian_elimination, lll, gram_schmidt
from shutil import get_terminal_size
from types import FunctionType

# Python's string interpolation doesn't like newlines...
NEWLINE = "\n"

class Matrix(RingElement):
    def __init__(self, rows: list, coeff_ring: Ring=None, ring: Ring=None):
        """
        Parameters:
            rows       (list): List of lists representing matrix rows.
            coeff_ring (Ring): Ring elements will be in.
            ring       (Ring): Parent ring.
        """
        from samson.math.algebra.rings.matrix_ring import MatrixRing

        is_coerced      = hasattr(rows[0][0], 'ring')
        self.coeff_ring = coeff_ring or (rows[0][0].ring if is_coerced else ZZ)
        row_lens        = [len(row) for row in rows]

        if not max(row_lens) == min(row_lens):
            raise ValueError("Row lengths must be equal")

        c_len = row_lens[0]
        r_len = len(rows)
        if not is_coerced:
            rows = [[self.coeff_ring.coerce(rows[r][c]) for c in range(c_len)] for r in range(r_len)]

        self.rows = rows

        if not ring and r_len == c_len:
            ring = MatrixRing(size=r_len, ring=ring)

        self.ring = ring


    def __repr__(self):
        max_elem_size = max([len(elem.shorthand()) for row in self.rows for elem in row])
        base_adjust   = min(max_elem_size, get_terminal_size().columns - 10)
        return f'<Matrix: rows={"".join([NEWLINE + "[" + ", ".join(([elem.shorthand().rjust(base_adjust) for elem in row])) + "]" for row in self.rows])}>'

    def __str__(self):
        return self.__repr__()


    @property
    def num_rows(self) -> int:
        return len(self.rows)


    @property
    def num_cols(self) -> int:
        return len(self.rows[0])


    def transpose(self) -> object:
        """
        Transposes the `Matrix` i.e. flips it along its diagonal.

        Returns:
            Matrix: Transposed `Matrix`.
        
        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2,3],[4,5,6],[7,8,9]], ZZ).transpose()
            <Matrix: rows=
            [ZZ(1), ZZ(4), ZZ(7)]
            [ZZ(2), ZZ(5), ZZ(8)]
            [ZZ(3), ZZ(6), ZZ(9)]>

        """
        return Matrix([[self.rows[r][c] for r in range(self.num_rows)] for c in range(self.num_cols)], coeff_ring=self.coeff_ring, ring=self.ring)


    @property
    def T(self) -> object:
        return self.transpose()


    def is_square(self) -> bool:
        """
        Determines whether the `Matrix` is square i.e. the number of columns equals the number of rows.

        Returns:
            bool: Whether the `Matrix` is square.
        """
        return self.num_cols == self.num_rows


    @staticmethod
    def identity(size: int, coeff_ring: Ring=None, ring: Ring=None) -> object:
        """
        Creates the identity `Matrix` of `size`.

        Parameters:
            size        (int): Number of rows/columns.
            coeff_ring (Ring): Ring elements will be in.
            ring       (Ring): Parent ring.
        
        Returns:
            Matrix: Identity matrix.
        """
        return Matrix([[coeff_ring.one() if r == c else coeff_ring.zero() for r in range(size)] for c in range(size)], coeff_ring=coeff_ring, ring=ring)


    @staticmethod
    def fill(value: object, rows: int, cols: int=None, coeff_ring: Ring=None, ring: Ring=None) -> object:
        """
        Fills a `Matrix` with `value`.

        Parameters:
            value    (object): Value every element should be.
            rows        (int): Number of rows.
            cols        (int): Number of columns.
            coeff_ring (Ring): Ring elements will be in.
            ring       (Ring): Parent ring.
        
        Returns:
            Matrix: `Matrix` filled with `value`.
        
        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix.fill(ZZ.zero(), 3, 4)
            <Matrix: rows=
            [ZZ(0), ZZ(0), ZZ(0), ZZ(0)]
            [ZZ(0), ZZ(0), ZZ(0), ZZ(0)]
            [ZZ(0), ZZ(0), ZZ(0), ZZ(0)]>

        """
        return Matrix([[value for c in range(cols or rows)] for r in range(rows)], coeff_ring=coeff_ring, ring=ring)


    def apply_elementwise(self, func: FunctionType) -> object:
        """
        Applies a function to each element and returns a `Matrix` of the results.

        Parameters:
            func (func): Function to apply.
        
        Returns:
            Matrix: Result matrix.
        
        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2,3],[4,5,6],[7,8,9]], ZZ).apply_elementwise(lambda elem: elem**2)
            <Matrix: rows=
            [ ZZ(1),  ZZ(4),  ZZ(9)]
            [ZZ(16), ZZ(25), ZZ(36)]
            [ZZ(49), ZZ(64), ZZ(81)]>

        """
        return Matrix([[func(self.rows[r][c]) for c in range(self.num_cols)] for r in range(self.num_rows)], coeff_ring=self.coeff_ring, ring=self.ring)


    def row_join(self, other: object) -> object:
        """
        Extends `self`'s rows with `others`.

        Parameters:
            other (Matrix): Other `Matrix`.
        
        Returns:
            Matrix: The joined matrices.
        
        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2], [3,4]], ZZ).row_join(Matrix([[5,6], [7,8]], ZZ))
            <Matrix: rows=
            [ZZ(1), ZZ(2), ZZ(5), ZZ(6)]
            [ZZ(3), ZZ(4), ZZ(7), ZZ(8)]>

        """
        type_o = type(other)

        if type_o is Matrix:
            cols = other.rows
        else:
            cols = other

        return Matrix([row_a + row_b for row_a, row_b in zip(self.rows, cols)], coeff_ring=self.coeff_ring, ring=self.ring)


    def col_join(self, other: object) -> object:
        """
        Extends `self`'s columns with `others`.

        Parameters:
            other (Matrix): Other `Matrix`.
        
        Returns:
            Matrix: The joined matrices.
        
        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2], [3,4]], ZZ).col_join(Matrix([[5,6], [7,8]], ZZ))
            <Matrix: rows=
            [ZZ(1), ZZ(2)]
            [ZZ(3), ZZ(4)]
            [ZZ(5), ZZ(6)]
            [ZZ(7), ZZ(8)]>

        """
        type_o = type(other)

        if type_o is Matrix:
            rows = other.rows
        else:
            rows = other

        return Matrix(self.rows + rows, coeff_ring=self.coeff_ring, ring=self.ring)


    def LLL(self, delta: float=0.75) -> object:
        """
        Performs the Lenstra–Lenstra–Lovász lattice basis reduction algorithm.

        Parameters:
            delta (float): Minimum optimality of the reduced basis.

        Returns:
            Matrix: Reduced basis.

        Examples:
            >>> from samson.math.matrix import Matrix
            >>> from samson.math.all import QQ
            >>> m = Matrix([[1, 2, 3, 4], [5, 6, 7, 8]], QQ)
            >>> m.LLL()
            <Matrix: rows=
            [ Frac(ZZ)(ZZ(3)/ZZ(1)),  Frac(ZZ)(ZZ(2)/ZZ(1)),  Frac(ZZ)(ZZ(1)/ZZ(1)),  Frac(ZZ)(ZZ(0)/ZZ(1))]
            [Frac(ZZ)(ZZ(-2)/ZZ(1)),  Frac(ZZ)(ZZ(0)/ZZ(1)),  Frac(ZZ)(ZZ(2)/ZZ(1)),  Frac(ZZ)(ZZ(4)/ZZ(1))]>
    
        """
        return lll(self, delta)


    def gram_schmidt(self, normalize: bool=True) -> object:
        """
        Performs Gram-Schmidt orthonormalization.

        Parameters:
            normalize (bool): Whether or not to normalize the vectors.
        
        Returns:
            Matrix: Orthonormalized row vectors.
        
        Examples:
            >>> from samson.math.all import QQ
            >>> from samson.math.matrix import Matrix
            >>> out = Matrix([[3,1],[2,2]], QQ).gram_schmidt()
            >>> [[float(out[r][c]) for c in range(out.num_cols)] for r in range(out.num_rows)]
            [[0.9486832980505138, 0.31622776601683794], [-0.31622776601683794, 0.9486832980505138]]

        """
        return gram_schmidt(self, normalize)


    # TODO: This only works with QQ since we're letting Python's `sqrt` function coerce it into a Python float.
    # The root problem is two-fold:
    # 1) Finding the square-root of an element in an arbitrary ring
    # 2) Handling irrational numbers

    # Python's floating-point arithmetic will automatically truncate irrational numbers to 53 bits, however, `Frac(ZZ)` will use arbitrary-precision integers
    # to represent the numerator and denominator, resulting in an infinite expansion.
    def normalize(self) -> object:
        """
        Normalizes the `Matrix` by dividing all elements by its magnitude.

        Returns:
            Matrix: Normalized `Matrix`.
        
        Examples:
            >>> from samson.math.all import QQ, Matrix
            >>> Matrix([[4,4,4,4]]*4, QQ).normalize()
            <Matrix: rows=
            [Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2))]
            [Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2))]
            [Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2))]
            [Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2)), Frac(ZZ)(ZZ(1)/ZZ(2))]>

        """
        from math import sqrt

        magnitude = self.coeff_ring(sqrt((self.apply_elementwise(lambda elem: elem**2)*Matrix.fill(self.coeff_ring.one(), rows=self.num_cols, cols=1))[0][0]))
        return self * ~magnitude


    def LUsolve(self, rhs: object) -> object:
        """
        Solves `Ax = b` for `x` where `A` is `self` and `b` is `rhs`.

        Parameters:
            rhs (Matrix): The right-hand side matrix.
        
        Returns
            Matrix: The `x` matrix.
        
        Examples:
            >>> from samson.math.all import QQ
            >>> from samson.math.matrix import Matrix
            >>> a = Matrix([[3, 2,-4], [2, 3, 3], [5, -3, 1]], coeff_ring=QQ)
            >>> b = Matrix([[3], [15], [14]], coeff_ring=QQ)
            >>> c = a.LUsolve(b)
            >>> a*c == b
            True

        """
        return gaussian_elimination(self, rhs)


    def __getitem__(self, idx) -> object:
        if type(idx) is tuple:
            if type(idx[0]) is slice:
                return [row[idx[1]] for row in self.rows[idx[0]]]
            else:
                return self.rows[idx[0]][idx[1]]
        else:
            return self.rows[idx]


    def __setitem__(self, idx, value) -> object:
        if type(idx) is int:
            self.rows[idx] = value
        elif type(idx) is tuple:
            self.rows[idx[0]][idx[1]] = value


    def __len__(self) -> int:
        return len(self.rows)

    def __or__(self, other: object) -> object:
        return self.col_join(other)

    def __neg__(self) -> object:
        return self.apply_elementwise(lambda elem: -elem)


    def __add__(self, other: object) -> object:
        if type(other) == type(self):
            return Matrix([[self.rows[r][c] + other.rows[r][c] for c in range(self.num_cols)] for r in range(self.num_rows)], coeff_ring=self.coeff_ring, ring=self.ring)
        else:
            raise ValueError("other type not addible")


    def __sub__(self, other: object) -> object:
        return self + -other


    def __mul__(self, other: object) -> object:
        if type(other) is Matrix:
            s_rows = self.num_rows
            s_cols = self.num_cols
            o_cols = other.num_cols
            o_rows = other.num_rows

            if s_cols != o_rows:
                raise ValueError(f"Cannot multiply {s_rows}x{s_cols} matrix by {o_rows}x{o_cols} matrix")

            ans = []
            for row in range(s_rows):
                ans.append([])
                for o_col in range(o_cols):
                    col_total = 0
                    for col in range(s_cols):
                        col_total += self.rows[row][col] * other.rows[col][o_col]

                    ans[-1].append(col_total)

            return Matrix(ans, coeff_ring=self.coeff_ring, ring=self.ring)

        else:
            return self.apply_elementwise(lambda elem: elem * other)


    def __invert__(self) -> object:
        return gaussian_elimination(self, Matrix.identity(len(self), coeff_ring=self.coeff_ring, ring=self.ring))


    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self * ~other


    def __floordiv__(self, other: object) -> object:
        return self / other


    def __eq__(self, other: object) -> object:
        return type(self) == type(other) and self.rows == other.rows
