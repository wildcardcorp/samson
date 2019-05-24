from enum import Enum

# TODO: Mod?
class Operation(Enum):
    ADD = ('{} + {}', 3)
    SUB = ('{} - {}', 3)
    MUL = ('{}*{}', 2)
    DIV = ('{}/{}', 2)
    POW = ('{}**{}', 1)
    NEG = ('-{}', 0)


class Expression(object):
    def __init__(self, a, b, operation: Operation):
        self.a = a
        self.b = b
        self.operation = operation


    def __repr__(self):
        exp_strs = []
        for operand in [self.a, self.b]:
            if operand:
                # If we have higher priority (lower number), then put parentheses around the next op.
                if type(operand) is Expression and self.operation.value[1] < operand.operation.value[1]:
                    exp_strs.append(f'({(operand)})')
                else:
                    exp_strs.append(str(operand))

        return self.operation.value[0].format(*exp_strs)

    def __str__(self):
        return self.__repr__()


    def simplify(self) -> object:
        pass


    def __add__(self, other: object) -> object:
        return Expression(self, other, Operation.ADD)

    def __radd__(self, other: object) -> object:
        return Expression(other, self, Operation.ADD)

    def __sub__(self, other: object) -> object:
        return Expression(self, other, Operation.SUB)

    def __rsub__(self, other: object) -> object:
        return Expression(other, self, Operation.SUB)

    def __mul__(self, other: object) -> object:
        return Expression(self, other, Operation.MUL)

    def __rmul__(self, other: object) -> object:
        return Expression(other, self, Operation.MUL)

    def __truediv__(self, other: object) -> object:
        return Expression(self, other, Operation.DIV)

    def __rtruediv__(self, other: object) -> object:
        return Expression(other, self, Operation.DIV)

    def __pow__(self, other: object) -> object:
        return Expression(self, other, Operation.POW)

    def __rpow__(self, other: object) -> object:
        return Expression(other, self, Operation.POW)

    def __neg__(self) -> object:
        return Expression(self, None, Operation.NEG)
