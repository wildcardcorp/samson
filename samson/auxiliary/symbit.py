from samson.core.base_object import BaseObject
from samson.math.polynomial import Polynomial
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.symbols import Symbol
from samson.utilities.bytes import Bytes
import linecache
from enum import Enum
import itertools
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


    c0, c1 = coeffs
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
        other = self._coerce(other)
        return SymBit(self.value * other.value)


    def __xor__(self, other):
        other = self._coerce(other)
        return SymBit(self.value + other.value)


    def __invert__(self):
        return SymBit(self.value + 1)


    def __or__(self, other):
        other = self._coerce(other)
        return (self ^ other) ^ (self & other)


    def __eq__(self, other):
        other = self._coerce(other)
        return self ^ ~other


    def __matmul__(self, other):
        other = self._coerce(other)
        return ~self | other
    

    def is_constant(self):
        return not bool(self.value[1]) and self.value[0] in (self.value.ring.zero, self.value.ring.one)
 

    def __bool__(self):
        return self.value.degree() == 0 and bool(self.value[0])


    def __hash__(self):
        return hash(self.value)
    

    def _coerce(self, other):
        if type(other) is int:
            return SymBit(self.value.ring([other]))
        else:
            return other


    def get_parameters(self):
        curr   = self.value
        params = []
        while type(curr) is Polynomial:
            params.append(curr.symbol.repr)
            curr = curr[0]
        
        return params[::-1]


    def reconstruct(self):
        params   = self.get_parameters()
        body     = parse_poly(self.value, _OP_MAP_SYM)
        params   = ', '.join(params)
        filename = f'<dynamic-{Bytes.random(8).hex().decode()}>'

        # Clean up function
        if body[0] == '(' and body[-1] == ')':
            body = body[1:-1]
        
        body = body.replace('& 1', '')
        body = body.replace('~~', '')


        if hasattr(self, 'func'):
            func_name = self.func.__name__
        else:
            func_name = f'dynamic_{Bytes.random(8).hex().decode()}'

        source = f'def {func_name}({params}):\n    return {body}'
        code   = compile(source, filename, 'exec')

        l = {}
        exec(code, {}, l)

        lines = [line + '\n' for line in source.splitlines()]

        linecache.cache[filename] = (len(source), None, lines, filename)
        return l[func_name]


    def build_output_table(self) -> 'IOTable':
        params = self.get_parameters()
        table  = {}
        for args in itertools.product(*[list(range(2)) for _ in range(len(params))]):
            table[args] = self(**dict(zip(params, args)))
        
        return IOTable(table, self.get_parameters())



def build_symbols(parameters: list) -> tuple:
    symbols = tuple([Symbol(param) for param in parameters])
    R = ZZ/ZZ(2)
    P = R[symbols]

    return [SymBit(P(sym)) for sym in symbols], SymBit(P.zero), SymBit(P.one)



class IOTable(BaseObject):
    def __init__(self, table: dict, symbols: list) -> None:
        self.table   = table
        self.symbols = symbols
    

    def pretty(self):
        from rich.table import Table
        from rich import print

        table = Table(title="Output Table", show_lines=True)

        styles  = itertools.cycle(["dim white", "green", "magenta", "yellow", "cyan", "dim white"])
        columns = self.symbols + ['Output']

        for name, style in zip(columns, styles):
            table.add_column(name, style="bold " + style, no_wrap=True)

        for args, output in self.table.items():
            table.add_row(*[str(a) for a in args], str(int(output)))

        print()
        print(table)



    def build_symbit(self) -> 'Symbits':
        symbols, zero, one = build_symbols(self.symbols)
        func = zero

        for k,v in self.table.items():
            curr = one
            if v:
                for sym, val in zip(symbols, k):
                    if not val:
                        sym = ~sym
                    
                    curr &= sym
                
                func ^= curr
        
        return func


    def serialize(self) -> Bytes:
        out_string = [None] * len(self.table)

        for in_args, output in self.table.items():
            pos = int(''.join([str(a) for a in in_args]), 2)
            out_string[pos] = int(output)

        return Bytes(len(self.symbols)) + Bytes(int(''.join([str(b) for b in out_string]), 2))


    @staticmethod
    def deserialize(in_bytes: bytes) -> 'IOTable':
        import string
        num_args = in_bytes[0]
        symbols  = string.ascii_letters[:num_args]
        outputs  = [int(b) for b in bin(Bytes.wrap(in_bytes[1:]).int())[2:].zfill(len(symbols))]

        return IOTable({tuple([int(b) for b in bin(i)[2:].zfill(len(symbols))]): o for i,o in enumerate(outputs)}, list(symbols))



class SymFunc(SymBit):
    def __init__(self, func) -> None:
        self.func = func
        self.sig  = inspect.signature(func)
        self.symbols, self.zero, self.one  = build_symbols(self.sig.parameters) 
        self.symbolic = func(*self.symbols)


    def __call__(self, *args, **kwargs):
        bound = self.sig.bind(*args, **kwargs)
        return self.symbolic(**bound.arguments)


    @property
    def value(self):
        return self.symbolic.value



def check_equiv(func1, func2, num_args):
    for args in itertools.product(*[list(range(2)) for _ in range(num_args)]):
        if (func1(*args) & 1) != (func2(*args) & 1):
            print(args)