from samson.math.algebra.rings.ring import Ring
from samson.math.general import fast_mul, square_and_mul
from samson.math.sparse_vector import SparseVector
from sympy import Expr, Symbol, Integer
from copy import deepcopy


class Polynomial(object):
    def __init__(self, coeffs: list, ring: Ring=None, symbol: Symbol=None):
        default_symbol = Symbol('x')
        self.ring = ring or coeffs[0].ring

        # Parse expressions
        if issubclass(type(coeffs), Expr):
            default_symbol = list(coeffs.free_symbols)[0]
            coeff_vec      = SparseVector([], self.ring.zero())

            for sub_expr, coeff in coeffs.as_coefficients_dict().items():
                coeff = self.ring.coerce(int(coeff))
                if issubclass(type(sub_expr), Integer):
                    coeff_vec[0] = coeff
                else:
                    coeff_vec[int(sub_expr.args[1] if sub_expr.args else 1)] = coeff
            
            self.coeffs = coeff_vec


        elif type(coeffs) is list or type(coeffs) is tuple:
            if len(coeffs) > 0 and type(coeffs[0]) is tuple:
                vec = coeffs
            else:
                vec = [self.ring.coerce(coeff) for coeff in coeffs]

            self.coeffs = SparseVector(vec, self.ring.zero())


        elif type(coeffs) is SparseVector:
            self.coeffs = coeffs

        
        self.symbol = symbol or default_symbol

        if len(self.coeffs.values) == 0:
            self.coeffs = SparseVector([self.ring.zero()], self.ring.zero())



    def shorthand(self) -> str:
        poly_repr = []
        if self.LC():
            for idx, coeff in self.coeffs.values.items():
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
        else:
            return self.ring.zero()


    def __repr__(self):
        return f"<Polynomial: {self.shorthand()}, ring={self.ring}>"

    def __str__(self):
        return self.__repr__()


    def __call__(self, x: int) -> object:
        return self.evaluate(x)


    def __hash__(self) -> int:
        return hash((self.ring, self.coeffs, self.__class__))


    def LC(self) -> object:
        try:
            return self.coeffs[-1]
        except IndexError:
            return self.ring.zero()


    def evaluate(self, x: object) -> object:
        """
        Evaluates the `Polynomial` at `x` using Horner's method.
        
        Parameters:
            x (object): Point to evaluate at.
        
        Returns:
            RingElement: Evaluation at `x`.
        """
        coeffs   = self.coeffs
        c0       = coeffs[-1]
        last_idx = coeffs.last()

        for idx, coeff in self.coeffs.values.items()[:-1][::-1]:
            c0 = coeff + c0*x**(last_idx-idx)
            last_idx = idx

        return c0


    def monic(self) -> object:
        return Polynomial([(idx, coeff / self.coeffs[-1]) for idx, coeff in self.coeffs], self.ring, self.symbol)


    def is_monic(self) -> bool:
        return self.LC() == self.ring.one()


    def derivative(self) -> object:
        return Polynomial([(idx-1, coeff * idx) for idx, coeff in self.coeffs][1:], self.ring, self.symbol)


    def degree(self) -> int:
        try:
            return self.coeffs.last()
        except IndexError:
            return 0


    def zero(self) -> object:
        return Polynomial([self.ring.zero()], self.ring, self.symbol)


    def __divmod__(self, other: object) -> (object, object):
        poly_zero = Polynomial([self.ring.zero()], symbol=self.symbol)
        assert other != poly_zero

        n = other.degree()
        if n > self.degree():
            return self.zero(), self

        dividend = deepcopy(self.coeffs)
        divisor  = other.coeffs

        n = other.degree()
        quotient = SparseVector([], self.ring.zero())

        for k in reversed(range(self.degree() - n + 1)):
            quotient[k] = dividend[k+n] / divisor[n]

            for j in range(k, k+n):
                dividend[j] -= quotient[k] * divisor[j-k]

        remainder = dividend[:n]

        return (Polynomial(quotient, ring=self.ring, symbol=self.symbol), Polynomial(remainder, ring=self.ring, symbol=self.symbol))


    def __add__(self, other: object) -> object:
        vec = SparseVector([], self.ring.zero())
        for idx, coeff in self.coeffs:
            vec[idx] = coeff + other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = coeff

        return Polynomial(vec, self.ring, self.symbol)


    def __sub__(self, other: object) -> object:
        vec = SparseVector([], self.ring.zero())
        for idx, coeff in self.coeffs:
            vec[idx] = coeff - other.coeffs[idx]
        
        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = -coeff

        return Polynomial(vec, self.ring, self.symbol)


    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return fast_mul(self, other, self.zero())

        new_coeffs = SparseVector([], self.ring.zero())

        for i, coeff_h in self.coeffs:
            for j, coeff_g in other.coeffs:
                new_coeffs[i+j] += coeff_h*coeff_g

        return Polynomial(new_coeffs, self.ring, self.symbol)


    def __rmul__(self, other: int) -> object:
        return self * other


    def __neg__(self) -> object:
        return Polynomial([(idx, -coeff) for idx, coeff in self.coeffs], self.ring, self.symbol)


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
        return self.coeffs != SparseVector([self.ring.zero()], self.ring.zero())
