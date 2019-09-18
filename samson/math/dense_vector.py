class DenseVector(object):
    def __init__(self, values: list):
        self.values = values


    def __repr__(self):
        return f'<DenseVector: values={self.values}>'

    def __str__(self):
        return self.__repr__()


    def __hash__(self) -> int:
        return hash(self.values)

    def __add__(self, other: object) -> object:
        return DenseVector([a+b for a,b in zip(self.values, other.values)])

    def __sub__(self, other: object) -> object:
        return DenseVector([a-b for a,b in zip(self.values, other.values)])

    def __neg__(self) -> object:
        return DenseVector([-a for a in self.values])

    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return DenseVector([a*other for a in self.values])

        raise NotImplementedError("Only scalar multiplication implemented")


    def dot(self, other: object) -> object:
        return sum([a*b for a,b in zip(self.values, other.values)])
