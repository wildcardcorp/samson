from samson.core.base_object import BaseObject
from samson.math.polynomial import Polynomial
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.symbols import Symbol
from samson.utilities.bytes import Bytes
import linecache
from enum import Enum
import inspect


class Op(Enum):
    AND = 0
    OR  = 1
    XOR = 2
    IMP = 3
    NOT = 4
    EQ  = 5


_OP_MAP_WORDS = {
    Op.AND: 'AND',
    Op.OR: 'OR',
    Op.XOR: 'XOR',
    Op.IMP: 'IMP',
    Op.NOT: 'NOT ',
    Op.EQ: 'EQ',
}

_OP_MAP_SYM = {
    Op.AND: '&',
    Op.OR: '|',
    Op.XOR: '^',
    Op.IMP: '@',
    Op.NOT: '~',
    Op.EQ: '==',
}


def parse_poly(poly, OP_MAP):
    coeffs  = list(poly)
    content = poly.content()

    if content > poly.coeff_ring.one:
        return f'{parse_poly(content, OP_MAP)} & {parse_poly(poly // content, OP_MAP)}'

    if type(coeffs[0]) is Polynomial:
        coeffs = [parse_poly(c, OP_MAP) for c in poly]


    if len(coeffs) == 1:
        coeffs += [0]


    print('Poly', poly)

    c0, c1 = coeffs
    print('c0', c0, type(c0))
    print('c1', c1, type(c1))
    if not c1 and not c0:
        return ''

    elif c1 and not c0:
        return poly.symbol.repr

    elif c1 and c0 and type(c0) is not str:
        return f'{OP_MAP[Op.NOT]}{poly.symbol.repr}'
    
    elif not c1 and c0 and type(c0) is not Polynomial:
        return '1'

    elif not c1 and c0:
        return c0.symbol.repr
    
    elif type(c0) is str and c0 and c1:
        
        c1_mod = f'{c1} {OP_MAP[Op.AND]} {poly.symbol.repr}'

        if type(c1) is str:
            if c1 == '1':
                c1_mod = f'{poly.symbol.repr}'
            elif c1 == '0':
                c1_mod = ''


        c0_mod = f' {OP_MAP[Op.XOR]} {c0}'
        if type(c0) is str:
            if c0 == '0':
                return f'{c1_mod}'
            elif c0 == '1':
                return f'~{c1_mod}'

        return f'({c1_mod}{c0_mod})'

    elif c0 and c1:
        return f'({c0} {OP_MAP[Op.XOR]} {c1})'



def collapse_poly(poly):
    if type(poly[0]) is Polynomial:
        poly = poly.map_coeffs(lambda i,c: (i, collapse_poly(c)))

    # Every degree > 1 is `x` AND `x`, AKA the identity!
    # We can collapse the coefficients above degree 0 into a new degree 1
    c1 = sum(list(poly >> 1))
    c0 = poly[0]
    return poly.ring([c0, c1])



class SymBit(BaseObject):
    def __init__(self, value) -> None:
        self.value = collapse_poly(value)


    def __call__(self, *args, **kwargs):
        return self.value(*args, **kwargs)


    def __and__(self, other):
        return SymBit(self.value * other.value)


    def __xor__(self, other):
        return SymBit(self.value + other.value)


    def __invert__(self):
        return SymBit(self.value + 1)


    def __or__(self, other):
        return (self ^ other) ^ (self & other)


    def __eq__(self, other):
        return self ^ ~other


    def __matmul__(self, other):
        return ~self | other
    

    def is_constant(self):
        return not bool(self.value[1]) and self.value[0] in (self.value.ring.zero, self.value.ring.one)
 

    def __bool__(self):
        return self.value.degree() == 0 and bool(self.value[0])


    def __hash__(self):
        return hash(self.value)


class SymFunc(SymBit):
    def __init__(self, func) -> None:
        self.func = func
        self.sig  = inspect.signature(func)
        symbols   = tuple([Symbol(param) for param in self.sig.parameters])
        R = ZZ/ZZ(2)
        P = R[symbols]

        self.symbols  = [SymBit(sym) for sym in symbols]
        self.symbolic = func(*self.symbols)

        self.one  = SymBit(P.one)
        self.zero = SymBit(P.zero)


    def __call__(self, *args, **kwargs):
        bound = self.sig.bind(*args, **kwargs)
        return self.symbolic(**bound.arguments)
    

    @property
    def value(self):
        return self.symbolic.value


    def reconstruct(self):
        body     = parse_poly(self.symbolic.value, _OP_MAP_SYM)
        params   = ', '.join(list(self.sig.parameters))
        filename = f'<dynamic-{Bytes.random(8).hex().decode()}>'

        if body[0] == '(' and body[-1] == ')':
            body = body[1:-1]

        source = f'def {self.func.__name__}({params}):\n    return {body}'
        code   = compile(source, filename, 'exec')

        l = {}
        exec(code, {}, l)

        lines = [line + '\n' for line in source.splitlines()]

        linecache.cache[filename] = (len(source), None, lines, filename)
        return l[self.func.__name__]



import itertools
def check_equiv(func1, func2, num_args):
    for args in itertools.product(*[list(range(2)) for _ in range(num_args)]):
        if (func1(*args) & 1) != (func2(*args) & 1):
            print(args)
