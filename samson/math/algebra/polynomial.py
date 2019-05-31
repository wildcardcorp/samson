from samson.math.algebra.rings.ring import Ring
from samson.math.general import fast_mul, square_and_mul
from sympy import Expr, Symbol

class Polynomial(object):
    def __init__(self, coeffs: list, ring: Ring=None, symbol: Symbol=None):
        default_symbol = Symbol('x')

        # Parse expressions
        if issubclass(type(coeffs), Expr):
            sym_poly       = coeffs.as_poly()
            coeffs         = [int(coeff) for coeff in sym_poly.all_coeffs()[::-1]]
            default_symbol = sym_poly.gens[0]

        self.ring   = ring or coeffs[0].ring
        self.symbol = symbol or default_symbol

        # Trim zeros
        coeffs_rev  = [self.ring.coerce(coeff) for coeff in coeffs][::-1]
        idx = 0
        while idx < len(coeffs) - 1 and coeffs_rev[idx] == self.ring.zero():
            idx += 1

        self.coeffs = coeffs_rev[idx:][::-1]

        if len(self.coeffs) == 0:
            self.coeffs = [self.ring.zero()]



    def shorthand(self) -> str:
        poly_repr = []
        for idx, coeff in enumerate(self.coeffs):
            if coeff == coeff.ring.zero() and not len(self.coeffs) == 1:
                continue

            if coeff == coeff.ring.one() and idx != 0:
                coeff_short_mul = ''
            else:
                coeff_short_mul = coeff.shorthand() + '*'

            if idx == 0:
                full_coeff = f'{coeff_short_mul[:-1]}'
            elif idx == 1:
                full_coeff = f'{coeff_short_mul}{self.symbol}'
            else:
                full_coeff = f'{coeff_short_mul}{self.symbol}**{idx}'

            poly_repr.append(full_coeff)

        return ' + '.join(poly_repr[::-1])


    def __repr__(self):
        return f"<Polynomial: {self.shorthand()}, ring={self.ring}>"

    def __str__(self):
        return self.__repr__()

    def __call__(self, x: int) -> object:
        return self.evaluate(x)


    def __hash__(self) -> int:
        return hash((self.ring, self.coeffs, self.__class__))


    def LC(self) -> object:
        return self.coeffs[-1]


    def evaluate(self, x: int) -> object:
        return sum([coeff*(x**idx) for idx, coeff in enumerate(self.coeffs)])


    def monic(self) -> object:
        return Polynomial([coeff / self.coeffs[-1] for coeff in self.coeffs], self.ring, self.symbol)


    def is_monic(self) -> bool:
        return self.LC() == self.ring.one()


    def derivative(self) -> object:
        return Polynomial([coeff * idx for idx, coeff in enumerate(self.coeffs)][1:], self.ring, self.symbol)


    def degree(self) -> int:
        return len(self.coeffs) - 1


    def pad(self, length: int) -> list:
        return self.coeffs + [self.ring.zero()] * (length - len(self.coeffs))


    def pad_and_zip(self, other: object) -> list:
        pad_len = max(len(self.coeffs), len(other.coeffs))
        return zip(self.pad(pad_len), other.pad(pad_len))


    def __divmod__(self, other: object) -> (object, object):
        poly_zero = Polynomial([self.ring.zero()], symbol=self.symbol)
        assert other != poly_zero

        dividend  = self.coeffs[:]
        divisor   = other.coeffs[:]

        n = other.degree()
        quotient = [self.ring.zero()] * (self.degree() - n + 1)

        for k in reversed(range(len(quotient))):
            quotient[k] = dividend[n+k] / divisor[n]

            for j in range(k, n+k):
                dividend[j] -= quotient[k] * divisor[j-k]

        remainder = dividend[:n]

        return (Polynomial(quotient, ring=self.ring, symbol=self.symbol), Polynomial(remainder, ring=self.ring, symbol=self.symbol))



    def __add__(self, other: object) -> object:
        return Polynomial([a + b for a,b in self.pad_and_zip(other)], self.ring, self.symbol)


    def __sub__(self, other: object) -> object:
        return Polynomial([a - b for a,b in self.pad_and_zip(other)], self.ring, self.symbol)


    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return fast_mul(self, other, Polynomial([self.ring.zero()], self.ring, self.symbol))

        new_coeff_len = max((len(self.coeffs) * len(other.coeffs) - 1), len(self.coeffs) + len(other.coeffs))
        new_coeffs    = [self.ring.zero()] * new_coeff_len

        for i, coeff_h in enumerate(self.coeffs):
            for j, coeff_g in enumerate(other.coeffs):
                new_coeffs[i+j] += coeff_h*coeff_g

        return Polynomial(new_coeffs, self.ring, self.symbol)


    def __rmul__(self, other: int) -> object:
        return self * other


    def __neg__(self) -> object:
        return Polynomial([-coeff for coeff in self.coeffs], self.ring, self.symbol)


    def __truediv__(self, other: object) -> object:
        return self.__divmod__(other)[0]


    __floordiv__ = __truediv__


    def __mod__(self, other: object) -> object:
        return self.__divmod__(other)[1]


    def __pow__(self, exponent: int) -> object:
        return square_and_mul(self, exponent, Polynomial([self.ring.one()], self.ring, self.symbol))


    def __int__(self) -> int:
        from samson.math.general import poly_to_int
        return poly_to_int(self)


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.coeffs == other.coeffs


    def __bool__(self) -> bool:
        return self.coeffs != [self.ring.zero()]
