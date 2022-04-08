from samson.core.base_object import BaseObject
from samson.analysis.general import hamming_weight
from samson.math.algebra.fields.finite_field import FiniteField as FF
from samson.math.symbols import Symbol
from samson.math.general import int_to_poly
from samson.math.matrix import Matrix
from samson.math.algebra.rings.integer_ring import ZZ
import math

class LinearApproximationTable(BaseObject):
    def __init__(self, table, sbox) -> None:
        self.table = table
        self.sbox  = sbox
    

    def pretty(self) -> str:
        import itertools
        from rich.table import Table
        from rich import print

        table = Table(title="Linear Approximation Table", show_lines=True)

        styles  = itertools.cycle(["dim white", "green", "magenta", "yellow", "cyan", "dim white"])
        columns = ['Mask'] + list(self.table)

        for name, style in zip(columns, styles):
            table.add_column(str(name), style="bold " + style, no_wrap=True)

        for imask, omask_table in self.table.items():
            table.add_row(str(imask), *[str(o) for o in omask_table.values()])

        print()
        print(table)


    def __getitem__(self, value):
        return self.table[value]


    def get_parity(self, value: int, mask: int):
        return hamming_weight(value & mask) % 2


    def test_parity(self, in_val: int, in_mask: int, out_mask: int):
        return self.get_parity(in_val, in_mask) == self.get_parity(self.sbox[in_val], out_mask)


    @staticmethod
    def from_sbox(sbox: 'SBox') -> 'LinearApproximationTable':
        lat = LinearApproximationTable({}, sbox)
        n   = len(sbox.forward)
        m   = n // 2

        for imask in range(1, n):
            lat.table[imask] = {}

            for omask in range(1, n):
                lat.table[imask][omask] = -m

                for i in range(n):
                    if lat.test_parity(i, imask, omask):
                        lat.table[imask][omask] += 1
                
                lat.table[imask][omask] /= m
        
        return lat


    def top_biases(self, num: int):
        t = []
        for imask, omask_table in self.table.items():
            for omask, prob in omask_table.items():
                t.append((imask, omask, prob))

        best_approx = sorted(t, key=lambda item: item[-1], reverse=True)
        return best_approx[:num]


class SBox(BaseObject):
    def __init__(self, values: list) -> None:
        if type(values) is list:
            values = {idx: val for idx, val in enumerate(values)}

        self.forward   = values
        self.backwards = {v:k for k,v in self.forward.items()}


    def __invert__(self):
        return SBox(self.backwards)
    

    def __getitem__(self, value):
        return self.forward[value]
    

    def io_size(self):
        def blen(a):
            return math.ceil(math.log2(a))

        return blen(len(self.forward)), blen(max(self.forward.values()))
    

    def linear_approximation(self):
        return LinearApproximationTable.from_sbox(self)


    lat = linear_approximation

    def polynomial(self):
        d = max(self.forward).bit_length()
        F = FF(2, d)
        P = F[Symbol('y')]

        points = [(F(int_to_poly(k, 2)), F(int_to_poly(v, 2))) for k,v in self.forward.items()]

        return P.interpolate(points)


    def difference_distribution_table(self):
        m, n = self.io_size()
        nrows = 2**m
        ncols = 2**n

        D = Matrix.fill(ZZ.zero, nrows, ncols)
        for i in range(nrows):
            a = self[i]
            for b in range(nrows):
                D[b, a^self[i^b]] += 1

        return D


    ddt = difference_distribution_table


    def autocorrelation_table(self):
        return self.ddt() * Matrix.hadamard(2**(self.io_size()[1]))
