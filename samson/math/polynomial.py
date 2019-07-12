from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import fast_mul, square_and_mul, gcd
from samson.math.sparse_vector import SparseVector
from sympy import Expr, Symbol, Integer, factorint
from copy import deepcopy


class Polynomial(RingElement):
    def __init__(self, coeffs: list, coeff_ring: Ring=None, symbol: Symbol=None, ring: Ring=None):
        default_symbol = Symbol('x')
        self.coeff_ring = coeff_ring or coeffs[0].ring

        # Parse expressions
        if issubclass(type(coeffs), Expr):
            default_symbol = list(coeffs.free_symbols)[0]
            coeff_vec      = SparseVector([], self.coeff_ring.zero())

            for sub_expr, coeff in coeffs.as_coefficients_dict().items():
                coeff = self.coeff_ring.coerce(int(coeff))
                if issubclass(type(sub_expr), Integer):
                    coeff_vec[0] = coeff
                else:
                    coeff_vec[int(sub_expr.args[1] if sub_expr.args else 1)] = coeff

            self.coeffs = coeff_vec


        elif type(coeffs) is list or type(coeffs) is tuple:
            if len(coeffs) > 0 and type(coeffs[0]) is tuple:
                vec = coeffs
            else:
                vec = [self.coeff_ring.coerce(coeff) for coeff in coeffs]

            self.coeffs = SparseVector(vec, self.coeff_ring.zero())


        elif type(coeffs) is SparseVector:
            self.coeffs = coeffs

        else:
            raise Exception(f"'coeffs' is not of an accepted type. Received {type(coeffs)}")


        self.symbol = symbol or default_symbol
        self.ring = ring or self.coeff_ring[self.symbol]

        if len(self.coeffs.values) == 0:
            self.coeffs = SparseVector([self.coeff_ring.zero()], self.coeff_ring.zero())



    def shorthand(self) -> str:
        poly_repr   = []
        poly_coeffs = type(self.LC()) is Polynomial

        if self.LC():
            for idx, coeff in self.coeffs.values.items():
                if coeff == coeff.ring.zero() and not len(self.coeffs) == 1:
                    continue

                if coeff == coeff.ring.one() and idx != 0:
                    coeff_short_mul = ''
                else:
                    shorthand = coeff.shorthand()
                    if poly_coeffs:
                        shorthand = f'({shorthand})'

                    coeff_short_mul = shorthand + '*'

                if idx == 0:
                    full_coeff = f'{coeff_short_mul[:-1]}'
                elif idx == 1:
                    full_coeff = f'{coeff_short_mul}{self.symbol}'
                else:
                    full_coeff = f'{coeff_short_mul}{self.symbol}**{idx}'

                poly_repr.append(full_coeff)

            return ' + '.join(poly_repr[::-1])
        else:
            return self.coeff_ring.zero().shorthand()


    def __repr__(self):
        return f"<Polynomial: {self.shorthand()}, coeff_ring={self.coeff_ring}>"

    def __str__(self):
        return self.__repr__()


    def __call__(self, x: int) -> object:
        return self.evaluate(x)


    def __hash__(self) -> int:
        return hash((self.coeff_ring, self.coeffs, self.__class__))


    def LC(self) -> object:
        try:
            return self.coeffs[-1]
        except IndexError:
            return self.coeff_ring.zero()


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
        return Polynomial([(idx, coeff / self.coeffs[-1]) for idx, coeff in self.coeffs], self.coeff_ring, self.symbol)


    def is_monic(self) -> bool:
        return self.LC() == self.coeff_ring.one()


    def derivative(self) -> object:
        return Polynomial([(idx-1, coeff * idx) for idx, coeff in self.coeffs if idx != 0], self.coeff_ring, self.symbol)


    def square_free_decomposition(self) -> list:
        """
        Examples:
            >>> from samson.math.all import Polynomial, ZZ
            >>> from sympy.abc import x
            >>> poly = Polynomial(3*x**3+x**7-x**18, ZZ)
            >>> poly.square_free_decomposition()
            [<Polynomial: x**15 + ZZ(-1)*x**4 + ZZ(-3), coeff_ring=ZZ>, <Polynomial: x**3, coeff_ring=ZZ>]

        """
        # https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization
        #R = 1
        c = gcd(self, self.derivative()).monic()
        w = self / c

        factors = []

        i = 1
        while w != self.ring.one():
            y = gcd(w, c).monic()
            fac = w / y
            #R *= fac**i
            factors.append(fac)
            w, c, i = y, c / y, i + 1

        if c != self.ring.one():
            # TODO: Take the p-th root
            c = c**(1/self.coeff_ring.characteristic)
            new_facs = c.square_free_decomposition()
            #R *= new_R**p
            factors.extend(new_facs)

        return [(fac**(idx+1)).monic() for idx, fac in enumerate(factors) if fac != self.ring.one()]


    def sff(self) -> list:
        return self.square_free_decomposition()


    def distinct_degree_factorization(self) -> list:
        # https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization
        f = self
        f_star = f
        S = []
        i = 1
        q = self.coeff_ring.characteristic

        x = self.symbol

        while f_star.degree() > 2*i:
            if not f_star.is_monic():
                f_star = f_star.monic()

            g = gcd(f_star, Polynomial(x**q**i - x, f.coeff_ring)).monic()
            if g != self.ring.one():
                S.append((g, i))
                f_star /= g

            i += 1

        if f_star != self.ring.one():
            S.append((f_star, f_star.degree()))

        if not S:
            return [(f, 1)]
        else:
            return S


    def ddf(self) -> list:
        return self.distinct_degree_factorization()


    # TODO: This method only works for FF due to `self.coeff_ring.order` and `f.coeff_ring.random(f.coeff_ring.reducing_poly.degree())`
    def equal_degree_factorization(self, d: int, subgroup_divisor: int=2) -> list:
        from samson.math.general import frobenius_map, frobenius_monomial_base

        f = self.monic()
        q = self.coeff_ring.order

        n = f.degree()
        r = n // d
        S = [f]

        f_quot   = f.ring / f
        exponent = (q - 1) // subgroup_divisor
        one      = self.ring.one()
        bases    = frobenius_monomial_base(f)

        irreducibility_cache = {}

        if n < d or self.is_irreducible():
            return S

        try:
            while len(S) < r and (not irreducibility_cache or not all([irreducibility_cache[poly] for poly in S])):
                h = Polynomial([f.coeff_ring.random(f.coeff_ring.reducing_poly.degree()) for _ in range(n)], f.coeff_ring)
                g = gcd(h, f).monic()

                if g == one:
                    h = f_quot(h)
                    j = h
                    for _ in range(d-1):
                        j = frobenius_map(j, f, bases=bases)
                        h *= j

                    g = (h**exponent).val - one

                for u in S:
                    if u.degree() <= d or (u in irreducibility_cache and irreducibility_cache[u]):
                        continue

                    gcd_g_u = gcd(g, u).monic()
                    if gcd_g_u != one and gcd_g_u != u:
                        S.remove(u)
                        if u in irreducibility_cache:
                            del irreducibility_cache[u]

                        u_gcd_g_u = u / gcd_g_u
                        S.extend([gcd_g_u, u_gcd_g_u])

                        # Cache irreducibility results
                        irreducibility_cache[gcd_g_u]   = gcd_g_u.is_irreducible()
                        irreducibility_cache[u_gcd_g_u] = u_gcd_g_u.is_irreducible()
        except KeyboardInterrupt:
            pass

        return S


    def edf(self, d: int, subgroup_divisor: int=2) -> list:
        return self.equal_degree_factorization(d, subgroup_divisor)


    def is_irreducible(self) -> bool:
        # https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Rabin's_test_of_irreducibility
        # https://github.com/sympy/sympy/blob/d1301c58be7ee4cd12fd28f1c5cd0b26322ed277/sympy/polys/galoistools.py
        from samson.math.general import frobenius_map, frobenius_monomial_base
        n = self.degree()

        if n <= 1:
            return True

        x = Symbol('x')
        f = self.monic()
        P = self.ring

        subgroups = {n // fac for fac in factorint(n)}

        bases  = frobenius_monomial_base(f)
        h      = bases[1]
        x_poly = P(x)
        one    = P.one()

        for idx in range(1, n):
            if idx in subgroups:
                if gcd(f, h - x_poly).monic() != one:
                    return False

            h = frobenius_map(h, f, bases=bases)

        return h == x_poly


    def is_prime(self) -> bool:
        return self.is_irreducible()


    def factor(self, d: int=1, subgroup_divisor: int=2) -> list:
        distinct_degrees = [factor for poly in self.sff() for factor in poly.ddf()]
        return [factor for poly, _ in distinct_degrees for factor in poly.edf(d, subgroup_divisor)]


    def degree(self) -> int:
        try:
            return self.coeffs.last()
        except IndexError:
            return 0


    def ordinality(self) -> int:
        return int(self)


    def __divmod__(self, other: object) -> (object, object):
        assert other != self.ring.zero()

        n = other.degree()
        if n > self.degree():
            return self.ring.zero(), self

        dividend = deepcopy(self.coeffs)
        divisor  = other.coeffs

        n = other.degree()
        quotient = SparseVector([], self.coeff_ring.zero())

        for k in reversed(range(self.degree() - n + 1)):
            quotient[k] = dividend[k+n] / divisor[n]

            for j in range(k, k+n):
                dividend[j] -= quotient[k] * divisor[j-k]

        remainder = dividend[:n]

        return (Polynomial(quotient, coeff_ring=self.coeff_ring, symbol=self.symbol), Polynomial(remainder, coeff_ring=self.coeff_ring, symbol=self.symbol))


    def __add__(self, other: object) -> object:
        vec = SparseVector([], self.coeff_ring.zero())
        for idx, coeff in self.coeffs:
            vec[idx] = coeff + other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = coeff

        return Polynomial(vec, self.coeff_ring, self.symbol)


    def __sub__(self, other: object) -> object:
        vec = SparseVector([], self.coeff_ring.zero())
        for idx, coeff in self.coeffs:
            vec[idx] = coeff - other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = -coeff

        return Polynomial(vec, self.coeff_ring, self.symbol)


    def __mul__(self, other: object) -> object:
        if type(other) is int:
            return fast_mul(self, other, self.ring.zero())

        new_coeffs = SparseVector([], self.coeff_ring.zero())

        for i, coeff_h in self.coeffs:
            for j, coeff_g in other.coeffs:
                new_coeffs[i+j] += coeff_h*coeff_g

        return Polynomial(new_coeffs, self.coeff_ring, self.symbol)


    def __rmul__(self, other: int) -> object:
        return self * other


    def __neg__(self) -> object:
        return Polynomial([(idx, -coeff) for idx, coeff in self.coeffs], self.coeff_ring, self.symbol)


    def __truediv__(self, other: object) -> object:
        return self.__divmod__(other)[0]


    __floordiv__ = __truediv__


    def __mod__(self, other: object) -> object:
        return self.__divmod__(other)[1]


    def __pow__(self, exponent: int) -> object:
        return square_and_mul(self, exponent, self.ring.one())


    def __int__(self) -> int:
        from samson.math.general import poly_to_int
        return poly_to_int(self)


    def __eq__(self, other: object) -> bool:
        return type(self) == type(other) and self.coeffs == other.coeffs


    def __lt__(self, other):
        return self.ordinality() < other.ordinality()



    def __gt__(self, other):
        return self.ordinality() > other.ordinality()



    def __bool__(self) -> bool:
        return self.coeffs != SparseVector([self.coeff_ring.zero()], self.coeff_ring.zero())


    def __lshift__(self, num: int):
        return Polynomial(SparseVector([(idx+num, coeff) for idx, coeff in self.coeffs], self.coeff_ring.zero()), coeff_ring=self.coeff_ring, ring=self.ring, symbol=self.symbol)

    def __rshift__(self, num: int):
        return Polynomial(SparseVector([(idx-num, coeff) for idx, coeff in self.coeffs[num:]], self.coeff_ring.zero()), coeff_ring=self.coeff_ring, ring=self.ring, symbol=self.symbol)
