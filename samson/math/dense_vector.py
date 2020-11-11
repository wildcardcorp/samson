from samson.utilities.runtime import RUNTIME

class DenseVector(object):
    def __init__(self, values: list):
        self.values = values


    def shorthand(self, tinyhand: bool=False) -> str:
        if tinyhand:
            str_meth = lambda elem: elem.tinyhand()
        else:
            str_meth = lambda elem: elem.shorthand()

        return "[" + ", ".join([str_meth(val) for val in self.values]) + "]"


    def tinyhand(self) -> str:
        return self.shorthand(True)


    def __repr__(self):
        return f'<DenseVector: values={RUNTIME.default_short_printer(self)}>'

    def __str__(self):
        return self.__repr__()


    def __hash__(self) -> int:
        return hash(self.values)

    def __add__(self, other: 'DenseVector') -> 'DenseVector':
        return DenseVector([a+b for a,b in zip(self.values, other.values)])

    def __sub__(self, other: 'DenseVector') -> 'DenseVector':
        return DenseVector([a-b for a,b in zip(self.values, other.values)])

    def __neg__(self) -> 'DenseVector':
        return DenseVector([-a for a in self.values])

    def __mul__(self, other: object) -> 'DenseVector':
        return DenseVector([a*other for a in self.values])


    def __iter__(self):
        return self.values.__iter__()


    def __getitem__(self, idx: object) -> 'RingElement':
        return self.values[idx]


    def __setitem__(self, idx, value):
        self.values[idx] = value


    def __len__(self):
        return len(self.values)


    def dot(self, other: 'DenseVector') -> object:
        if hasattr(self.values[0], 'ring'):
            zero = self.values[0].ring.zero
        else:
            zero = 0

        return sum([a*b for a,b in zip(self.values, other.values)], zero)


    def sdot(self) -> object:
        return self.dot(self)


    def prof_coeff(self, other: 'DenseVector') -> object:
        return self.dot(other) / self.sdot()


    def project(self, other: 'DenseVector') -> 'DenseVector':
        return self.prof_coeff(other) * self
