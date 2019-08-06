from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import square_and_mul, gcd, factor as factor_int
from samson.math.sparse_vector import SparseVector
from samson.utilities.general import add_or_increment

class Polynomial(RingElement):
    def __init__(self, coeffs: list, coeff_ring: Ring=None, symbol: object=None, ring: Ring=None):
        """
        Parameters:
            coeffs (list or Expr): Coefficients of the polynomial as a list of increasing degree or an expression.
            coeff_ring     (Ring): Ring the coefficients are in.
            symbol       (Symbol): Symbol to use as the indeterminate.
            ring           (Ring): Parent PolynomialRing.
        """
        from samson.math.symbols import Symbol

        self.coeff_ring = coeff_ring or coeffs[0].ring

        if type(coeffs) is list or type(coeffs) is tuple or type(coeffs) is dict:
            if type(coeffs) is dict or (len(coeffs) > 0 and type(coeffs[0]) is tuple):
                vec = coeffs
            else:
                vec = [self.coeff_ring.coerce(coeff) for coeff in coeffs]

            self.coeffs = SparseVector(vec, self.coeff_ring.zero())

        elif type(coeffs) is SparseVector:
            self.coeffs = coeffs

        else:
            raise Exception(f"'coeffs' is not of an accepted type. Received {type(coeffs)}")


        self.symbol = symbol or Symbol('x')
        self.ring   = ring or self.coeff_ring[self.symbol]

        if len(self.coeffs.values) == 0:
            self.coeffs = SparseVector([self.coeff_ring.zero()], self.coeff_ring.zero())



    def shorthand(self) -> str:
        poly_repr   = []
        poly_coeffs = type(self.LC().get_ground()) is Polynomial

        if self.LC():
            for idx, coeff in self.coeffs.values.items():
                if coeff == coeff.ring.zero() and not len(self.coeffs) == 1:
                    continue

                if coeff == coeff.ring.one() and idx != 0:
                    coeff_short_mul = ''
                else:
                    shorthand = coeff.shorthand()
                    if poly_coeffs and idx != 0:
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


    def LC(self) -> RingElement:
        """
        Returns the leading coefficient.

        Returns:
            RingElement: Coefficient of the highest degree.
        """
        try:
            return self.coeffs[-1]
        except IndexError:
            return self.coeff_ring.zero()


    def evaluate(self, x: object) -> RingElement:
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
        """
        Returns the Polynomial in its monic representation (leading coefficient is 1).

        Returns:
            Polynomial: Monic representation of self.
        """
        return Polynomial([(idx, coeff / self.coeffs[-1]) for idx, coeff in self.coeffs], self.coeff_ring, self.symbol)


    def is_monic(self) -> bool:
        """
        Determines whether or not the Polynomial is monic.

        Returns:
            bool: Whether or not the Polynomial is monic
        """
        return self.LC() == self.coeff_ring.one()


    def derivative(self) -> object:
        """
        Returns the derivative of the Polynomial.

        Returns:
            Polynomial: Derivative of self.
        """
        return Polynomial([(idx-1, coeff * idx) for idx, coeff in self.coeffs if idx != 0], self.coeff_ring, self.symbol)


    def trunc_kth_root(self, k: int) -> object:
        """
        Calculates an inexact `k`-th root.

        Parameters:
            k (int): Root to take.
        
        Returns:
            Polynomial: `k`-th root.
        
        Examples:
            >>> from samson.math.polynomial import Polynomial
            >>> from samson.math.algebra.rings.integer_ring import ZZ
            >>> from samson.math.symbols import Symbol
            >>> x = Symbol('x')
            >>> ZZ[x](x**4 + 2*x**2).trunc_kth_root(2)
            <Polynomial: x**2 + ZZ(2)*x, coeff_ring=ZZ>

        """
        return Polynomial([(idx // k, coeff) for idx, coeff in self.coeffs if not idx % k], self.coeff_ring, self.symbol)


    def trunc(self, mod: RingElement) -> object:
        """
        Reduces (modulo) the Polynomial's coefficients by `mod`.

        Parameters:
            mod (RingElement): Modulus.
        
        Returns:
            Polynomial: Polynomial with reduced coefficients.
        
        Examples:
            >>> from samson.math.algebra.rings.integer_ring import ZZ
            >>> from samson.math.symbols import Symbol
            >>> x = Symbol('x')
            >>> _ = ZZ[x]
            >>> (5*x**5 + 4*x**4 + 3*x**3 + 2*x**2 + x + 1).trunc(3)
            <Polynomial: ZZ(2)*x**5 + x**4 + ZZ(2)*x**2 + x + ZZ(1), coeff_ring=ZZ>

        """
        return Polynomial([(idx, coeff % mod) for idx, coeff in self.coeffs], self.coeff_ring, self.symbol)


    def square_free_decomposition(self) -> list:
        """
        Decomposes a Polynomial into its square-free factors. Used as the first step in factorization.

        https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization

        Returns:
            list: Square-free factors of self.

        Examples:
            >>> from samson.math.all import Polynomial, ZZ
            >>> from samson.math.symbols import Symbol
            >>> x = Symbol('x')
            >>> _ = ZZ[x]
            >>> poly = 3*x**3+x**7-x**18
            >>> poly.square_free_decomposition()
            {<Polynomial: x**15 + ZZ(-1)*x**4 + ZZ(-3), coeff_ring=ZZ>: 1, <Polynomial: x, coeff_ring=ZZ>: 3}

        """
        f = self.monic()
        c = gcd(f, f.derivative().monic()).monic()
        w = f / c

        factors = {}

        i = 1
        while w != self.ring.one():
            y = gcd(w, c).monic()
            fac = (w / y).monic()

            if fac != self.ring.one():
                add_or_increment(factors, fac, i)

            w, c, i = y, c / y, i + 1

        if c != self.ring.one():
            c        = c.trunc_kth_root(self.coeff_ring.characteristic)
            new_facs = c.square_free_decomposition()
            for new_fac in new_facs:
                add_or_increment(factors, new_fac, self.coeff_ring.characteristic)

        return factors


    def sff(self) -> list:
        """
        See `square_free_decomposition`.
        """
        return self.square_free_decomposition()


    def distinct_degree_factorization(self) -> list:
        """
        Factors a Polynomial into factors of different degrees.

        https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization

        Returns:
            list: Distinct-degree factors of self.
        """
        from samson.math.general import frobenius_map, frobenius_monomial_base

        f = self
        f_star = f
        S = []
        i = 1

        x = self.symbol
        x_poly = f.ring(x)

        while f_star.degree() > 2*i:
            if not f_star.is_monic():
                f_star = f_star.monic()

            # Calculate P(x**q**i - x)
            bases = frobenius_monomial_base(f_star)
            h     = frobenius_map(bases[1], f_star, bases=bases)

            for _ in range(i-1):
                h = frobenius_map(h, f_star, bases=bases)

            g = gcd(f_star, h - x_poly).monic()

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
        """
        See `distinct_degree_factorization`.
        """
        return self.distinct_degree_factorization()


    def equal_degree_factorization(self, d: int, subgroup_divisor: int=None) -> list:
        """
        Factors a Polynomial into factors of equal degrees.

        Parameters:
            d                (int): Degree to factor into.
            subgroup_divisor (int): Smallest divisor of `order - 1`.

        Returns:
            list: Equal-degree factors of self.
        """
        from samson.math.general import frobenius_map, frobenius_monomial_base
        from samson.math.symbols import oo

        f = self.monic()
        n = f.degree()
        r = n // d
        S = [f]

        f_quot   = f.ring / f
        if self.coeff_ring.order != oo:
            q = self.coeff_ring.order
            if not subgroup_divisor:
                subgroup_divisor = [f for f in factor_int((q - 1))][0]

            exponent = (q - 1) // subgroup_divisor

        one   = self.ring.one()
        bases = frobenius_monomial_base(f)

        irreducibility_cache = {}

        if n < d or self.is_irreducible():
            return S

        try:
            while len(S) < r and (not irreducibility_cache or not all([irreducibility_cache[poly] for poly in S])):
                h = f.ring.random(f)
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


    def edf(self, d: int, subgroup_divisor: int=None) -> list:
        """
        See `equal_degree_factorization`.
        """
        return self.equal_degree_factorization(d, subgroup_divisor)


    def is_irreducible(self) -> bool:
        """
        Determines if a Polynomial is irreducible over its ring.

        https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Rabin's_test_of_irreducibility
        https://github.com/sympy/sympy/blob/d1301c58be7ee4cd12fd28f1c5cd0b26322ed277/sympy/polys/galoistools.py

        Returns:
            bool: Whether or not the Polynomial is irreducible over its ring.
        """
        from samson.math.general import frobenius_map, frobenius_monomial_base

        n = self.degree()

        if n <= 1:
            return True

        x = self.symbol
        f = self.monic()
        P = self.ring

        subgroups = {n // fac for fac in factor_int(n)}

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
        """
        See `is_irreducible`.
        """
        return self.is_irreducible()


    def factor(self, d: int=1, subgroup_divisor: int=None) -> list:
        """
        Factors the Polynomial into its constituent, irreducible factors.

        Parameters:
            d                (int): Degree to factor into.
            subgroup_divisor (int): Smallest divisor of `order - 1`.

        Returns:
            list: Factors.

        Example:
            >>> from samson.math.algebra.all import *
            >>> from samson.math.symbols import Symbol
            >>> from functools import reduce
            >>> x = Symbol('x')
            >>> Z7 = ZZ/ZZ(7)
            >>> P  = Z7[x]

            >>> # Generate random factors
            >>> factors = [fac for fac in [P.random(P(x**3)) for _ in range(4)] if fac]
            >>> p = reduce(Polynomial.__mul__, factors, P[1]) # Build the Polynomial
            >>> reduce(Polynomial.__mul__, [fac**exp for fac, exp in p.factor().items()], P[1]) == p.monic() # Check the factorization is right
            True

        """
        factors = {}
        distinct_degrees = [(factor, num) for poly, num in self.sff().items() for factor in poly.ddf()]
        for (poly, _), num in distinct_degrees:
            for factor in poly.edf(d, subgroup_divisor):
                if factor != self.ring.one():
                    add_or_increment(factors, factor, num)

        return factors


    def degree(self) -> int:
        """
        Return the degree of the Polynomial.

        Returns:
            int: Degree.
        """
        try:
            return self.coeffs.last()
        except IndexError:
            return 0


    def ordinality(self) -> int:
        """
        Returns the ordinality of the Polynomial within its PolynomialRing.

        Returns:
            int: Ordinality.
        """
        return int(self)


    def embed_coeffs(self, ring: Ring) -> object:
        """
        Returns a new Polynomial with the coefficients coerced into `ring`.

        Parameters:
            ring (Ring): Ring to embed into.
        
        Returns:
            Polynomial: Resultant Polynomial.

        Examples:
            >>> from samson.math.all import *
            >>> x = Symbol('x')
            >>> _ = ZZ[x]
            >>> p = x**4 + x**2 + 1
            >>> p.embed_coeffs(ZZ/ZZ(2))
            <Polynomial: x**4 + x**2 + ZZ(1), coeff_ring=ZZ/ZZ(2)>

        """
        return Polynomial({idx: ring(coeff) for idx, coeff in self.coeffs})


    def peel_coeffs(self) -> object:
        """
        Returns a new Polynomial with the coefficients peeled from their ring.

        Returns:
            Polynomial: Resultant Polynomial.
        
            Examples:
            >>> from samson.math.all import *
            >>> x = Symbol('x')
            >>> _ = (ZZ/ZZ(2))[x]
            >>> p = x**4 + x**2 + 1
            >>> p.peel_coeffs()
            <Polynomial: x**4 + x**2 + ZZ(1), coeff_ring=ZZ>

        """
        return Polynomial({idx: coeff.val for idx, coeff in self.coeffs})


    def __divmod__(self, other: object) -> (object, object):
        other = self.ring.coerce(other)
        assert other != self.ring.zero()

        n = other.degree()
        if n > self.degree():
            return self.ring.zero(), self

        dividend = SparseVector([c for c in self.coeffs], self.coeff_ring.zero())
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
        other = self.ring.coerce(other)

        vec = SparseVector([], self.coeff_ring.zero())
        for idx, coeff in self.coeffs:
            vec[idx] = coeff + other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = coeff

        return Polynomial(vec, self.coeff_ring, self.symbol)


    def __sub__(self, other: object) -> object:
        other = self.ring.coerce(other)

        vec = SparseVector([], self.coeff_ring.zero())
        for idx, coeff in self.coeffs:
            vec[idx] = coeff - other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = -coeff

        return Polynomial(vec, self.coeff_ring, self.symbol)


    def __mul__(self, other: object) -> object:
        gmul = self.ground_mul(other)
        if gmul:
            return gmul

        other = self.ring.coerce(other)

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


    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        return self != self.ring.zero() and all([coeff.is_invertible() for _, coeff in self.coeffs])
