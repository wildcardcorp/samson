from samson.math.algebra.expression import Expression#, Operation

class Infinity(object):
    def __repr__(self):
        return '∞'

    def __str__(self):
        return self.__repr__()

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return self != other

    def __neg__(self):
        return NegativeInfinity()


class NegativeInfinity(object):
    def __repr__(self):
        return '-∞'

    def __str__(self):
        return self.__repr__()

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return self != other

    def __neg__(self):
        return Infinity()


class Symbol(Expression):
    def __init__(self, str_representation):
        self.repr = str_representation

    def __repr__(self):
        return self.repr

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.repr == other.repr


oo = Infinity()
