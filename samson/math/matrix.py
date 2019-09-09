from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import gaussian_elimination

# Python's string interpolation doesn't like newlines...
NEWLINE = "\n"

class Matrix(RingElement):
    def __init__(self, rows: list, coeff_ring: Ring=None, ring: Ring=None):
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
        return f'<Matrix: rows={"".join([NEWLINE + "[" + ", ".join(([elem.shorthand() for elem in row])) + "]" for row in self.rows])}>'

    def __str__(self):
        return self.__repr__()


    @property
    def num_rows(self) -> int:
        return len(self.rows)


    @property
    def num_cols(self) -> int:
        return len(self.rows[0])
    

    def transpose(self) -> object:
        return Matrix([[self.rows[r][c] for r in range(self.num_rows)] for c in range(self.num_cols)], coeff_ring=self.coeff_ring, ring=self.ring)
    
    
    @property
    def T(self) -> object:
        return self.transpose()


    def is_square(self) -> bool:
        return self.num_cols == self.num_rows


    @staticmethod
    def identity(size: int, coeff_ring: Ring=None, ring: Ring=None) -> object:
        return Matrix([[coeff_ring.one() if r == c else coeff_ring.zero() for r in range(size)] for c in range(size)], coeff_ring=coeff_ring, ring=ring)


    @staticmethod
    def fill(value: object, rows: int, cols: int=None, coeff_ring: Ring=None, ring: Ring=None) -> object:
        return Matrix([[value for c in range(cols or rows)] for r in range(rows)], coeff_ring=coeff_ring, ring=ring)
    

    def apply_elementwise(self, func) -> object:
        return Matrix([[func(self.rows[r][c]) for c in range(self.num_cols)] for r in range(self.num_rows)], coeff_ring=self.coeff_ring, ring=self.ring)


    def col_join(self, other: object) -> object:
        type_o = type(other)

        if type_o is Matrix:
            cols = other.rows
        else:
            cols = other
        
        return Matrix([row_a + row_b for row_a, row_b in zip(self.rows, cols)], coeff_ring=self.coeff_ring, ring=self.ring)


    def row_join(self, other: object) -> object:
        type_o = type(other)

        if type_o is Matrix:
            rows = other.rows
        else:
            rows = other
        
        return Matrix(self.rows + rows, coeff_ring=self.coeff_ring, ring=self.ring)


    def __getitem__(self, idx) -> object:
        return self.rows[idx]

    def __setitem__(self, idx, value) -> object:
        self.rows[idx] = value
    
    def __len__(self) -> int:
        return len(self.rows)
    
    def __or__(self, other: object) -> object:
        return self.col_join(other)

    def __neg__(self) -> object:
        return self.apply_elementwise(lambda elem: -elem)
        #return Matrix([[-self.rows[r][c] for c in range(self.num_cols)] for r in range(self.num_rows)], coeff_ring=self.coeff_ring, ring=self.ring)


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
            #return Matrix([[self.rows[r][c] * other for c in range(self.num_cols)] for r in range(self.num_rows)], coeff_ring=self.coeff_ring, ring=self.ring)



    def __invert__(self) -> object:
        return gaussian_elimination(self, Matrix.identity(len(self), coeff_ring=self.coeff_ring, ring=self.ring))


    def __truediv__(self, other: object) -> object:
        other = self.ring.coerce(other)
        return self * ~other


    def __floordiv__(self, other: object) -> object:
        return self / other


    def __eq__(self, other: object) -> object:
        return type(self) == type(other) and self.rows == other.rows
