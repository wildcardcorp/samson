from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import square_and_mul, gcd, factor as factor_int
from samson.math.sparse_vector import SparseVector
from samson.utilities.general import add_or_increment
from types import FunctionType

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
        c_type = type(coeffs)

        if c_type in [list, tuple, dict]:
            if c_type is dict or (len(coeffs) > 0 and type(coeffs[0]) is tuple):
                vec = coeffs
            else:
                vec = [self.coeff_ring.coerce(coeff) for coeff in coeffs]

            self.coeffs = self._create_sparse(vec)

        elif c_type is SparseVector:
            self.coeffs = coeffs

        else:
            raise Exception(f"'coeffs' is not of an accepted type. Received {type(coeffs)}")


        self.symbol = symbol or Symbol('x')
        self.ring   = ring or self.coeff_ring[self.symbol]
        self.coeffs.trim()

        if len(self.coeffs.values) == 0:
            self.coeffs = self._create_sparse([self.coeff_ring.zero])



    def shorthand(self, tinyhand: bool=False) -> str:
        poly_repr   = []
        poly_coeffs = type(self.LC().get_ground()) is Polynomial

        if self.LC():
            for idx, coeff in self.coeffs.values.items():
                if coeff == coeff.ring.zero and not len(self.coeffs) == 1:
                    continue

                if coeff == coeff.ring.one and idx != 0:
                    coeff_short_mul = ''
                else:
                    if tinyhand:
                        shorthand = coeff.tinyhand()
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
            return self.coeff_ring.zero.shorthand()



    def tinyhand(self) -> str:
        return self.shorthand(True)


    def __repr__(self):
        from samson.utilities.runtime import RUNTIME
        return f"<Polynomial: {RUNTIME.default_short_printer(self)}, coeff_ring={self.coeff_ring}>"

    def __str__(self):
        from samson.utilities.runtime import RUNTIME
        return RUNTIME.default_short_printer(self)


    def __call__(self, x: int) -> RingElement:
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
            return self.coeffs[self.coeffs.last()]
        except IndexError:
            return self.coeff_ring.zero


    def evaluate(self, x: RingElement) -> RingElement:
        """
        Evaluates the `Polynomial` at `x` using Horner's method.
        
        Parameters:
            x (RingElement): Point to evaluate at.
        
        Returns:
            RingElement: Evaluation at `x`.
        """
        coeffs   = self.coeffs
        c0       = coeffs[-1]
        last_idx = coeffs.last()
        idx      = None

        for idx, coeff in self.coeffs.values.items()[:-1][::-1]:
            c0 = coeff + c0*x**(last_idx-idx)
            last_idx = idx

    
        # Handle the case where there's only one coeff
        if idx is None:
            c0 *= x**last_idx

        return c0
    

    def valuation(self):
        from samson.math.algebra.symbols import oo

        if not self.coeffs:
            return oo
        
        return min(self.coeffs)
    


    def hensel_lift(self, p, a):
        a_eval   = self(a)
        f_prime  = self.derivative()
        der_eval = f_prime(a)

        if a_eval.valuation(p) < 2*der_eval.valuation(p):
            raise ValueError('a is not close enough to a root')

        b = ~der_eval

        while True:
            na = a - a_eval*b

            if na == a:
                return a

            a        = na
            a_eval   = self(a)
            der_eval = f_prime(a)
            b       *= 2 - der_eval*b

            print('a', a)
            print('a_eval', a_eval)
            print('der_eval', der_eval)
            print('b', b)
            print()



    def _create_sparse(self, vec):
        return SparseVector(vec, self.coeff_ring.zero, allow_virtual_len=True)


    def _create_poly(self, vec):
        return Polynomial(vec, coeff_ring=self.coeff_ring, ring=self.ring, symbol=self.symbol)


    def map_coeffs(self, func: FunctionType) -> 'Polynomial':
        return self._create_poly(self.coeffs.map(func))


    def monic(self) -> 'Polynomial':
        """
        Returns the Polynomial in its monic representation (leading coefficient is 1).

        Returns:
            Polynomial: Monic representation of self.
        """
        return self._create_poly([(idx, coeff / self.coeffs[-1]) for idx, coeff in self.coeffs])


    def is_monic(self) -> bool:
        """
        Determines whether or not the Polynomial is monic.

        Returns:
            bool: Whether or not the Polynomial is monic
        """
        return self.LC() == self.coeff_ring.one


    def derivative(self) -> 'Polynomial':
        """
        Returns the derivative of the Polynomial.

        Returns:
            Polynomial: Derivative of self.
        """
        return self._create_poly([(idx-1, coeff * idx) for idx, coeff in self.coeffs if idx != 0])


    def trunc_kth_root(self, k: int) -> 'Polynomial':
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
        return self._create_poly([(idx // k, coeff) for idx, coeff in self.coeffs if not idx % k])


    def trunc(self, mod: RingElement) -> 'Polynomial':
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
        return self._create_poly([(idx, coeff % mod) for idx, coeff in self.coeffs])


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
        while w != self.ring.one:
            y = gcd(w, c).monic()
            fac = (w / y).monic()

            if fac != self.ring.one:
                add_or_increment(factors, fac, i)

            w, c, i = y, c / y, i + 1

        if c != self.ring.one:
            if self.coeff_ring.characteristic:
                c = c.trunc_kth_root(self.coeff_ring.characteristic)

            new_facs = c.square_free_decomposition()
            for new_fac in new_facs:
                add_or_increment(factors, new_fac, self.coeff_ring.characteristic or 1)

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

            if g != self.ring.one:
                S.append((g, i))
                f_star /= g

            i += 1

        if f_star != self.ring.one:
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

        one   = self.ring.one
        bases = frobenius_monomial_base(f)

        irreducibility_cache = {}

        if n < d or self.is_irreducible():
            return S

        # We check here and not above because it's possible the poly is already irreducible
        if self.coeff_ring.order == oo:
            raise NotImplementedError('Currently can\'t factor polynomials in rings of infinite order')

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

        Returns:
            bool: Whether or not the Polynomial is irreducible over its ring.
        
        References:
            https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Rabin's_test_of_irreducibility
            https://github.com/sympy/sympy/blob/d1301c58be7ee4cd12fd28f1c5cd0b26322ed277/sympy/polys/galoistools.py
            https://en.wikipedia.org/wiki/Irreducible_polynomial#Over_the_integers_and_finite_field
        """
        from samson.math.general import frobenius_map, frobenius_monomial_base, find_coprime
        from samson.math.algebra.rings.integer_ring import ZZ

        n = self.degree()

        if n <= 1:
            return True

        # If dealing with the integers, we can convert into FF.
        #   From Wikipedia:
        #   "The irreducibility of a polynomial over the integers Z
        #   is related to that over the field F_p of `p` elements
        #   (for a prime `p`). In particular, if a univariate polynomial `f` over Z
        #   is irreducible over F_p for some prime `p` that does not
        #   divide the leading coefficient of `f` (the coefficient of the highest power of the variable),
        #   then f is irreducible over Z."
        if self.coeff_ring == ZZ:
            lc = int(self.LC())
            p  = 2

            if lc != 1:
                p = find_coprime(lc, range(1, lc**2))

            field = ZZ/ZZ(p)
            poly  = self.embed_coeffs(field)
        else:
            poly = self


        x = poly.symbol
        f = poly.monic()
        P = poly.ring

        subgroups = {n // fac for fac in factor_int(n)}

        bases  = frobenius_monomial_base(f)
        h      = bases[1]
        x_poly = P(x)
        one    = P.one

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
                if factor != self.ring.one:
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


    def embed_coeffs(self, ring: Ring) -> 'Polynomial':
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


    def peel_coeffs(self) -> 'Polynomial':
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


    def __divmod__(self, other: 'Polynomial') -> ('Polynomial', 'Polynomial'):
        other = self.ring.coerce(other)
        assert other != self.ring.zero

        n = other.degree()
        if n > self.degree():
            return self.ring.zero, self

        dividend = self._create_sparse([c for c in self.coeffs])
        divisor  = other.coeffs

        n = other.degree()
        quotient = self._create_sparse([])

        for k in reversed(range(self.degree() - n + 1)):
            quotient[k] = dividend[k+n] / divisor[n]

            for j in range(k, k+n):
                dividend[j] -= quotient[k] * divisor[j-k]

        remainder = dividend[:n]

        return (self._create_poly(quotient), self._create_poly(remainder))


    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        other = self.ring.coerce(other)

        vec = self._create_sparse([])
        for idx, coeff in self.coeffs:
            vec[idx] = coeff + other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = coeff

        return self._create_poly(vec)


    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        other = self.ring.coerce(other)

        vec = self._create_sparse([])
        for idx, coeff in self.coeffs:
            vec[idx] = coeff - other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = -coeff

        return self._create_poly(vec)



    def __mul__(self, other: object) -> object:
        from samson.utilities.runtime import RUNTIME

        gmul = self.ground_mul(other)
        if gmul:
            return gmul

        other = self.ring.coerce(other)

        if not RUNTIME.poly_fft_heuristic(self, other):
            # Naive convolution
            new_coeffs = self._create_sparse([])

            for i, coeff_h in self.coeffs:
                for j, coeff_g in other.coeffs:
                    new_coeffs[i+j] += coeff_h*coeff_g

            poly = self._create_poly(new_coeffs)

        else:
            # FFT conv
            from samson.math.general import gcd
            from samson.math.fft import _convolution

            self_powers  = list(self.coeffs.values.keys())
            other_powers = list(other.coeffs.values.keys())

            # Remove consistent sparsity (GCD)
            denom = min(self_powers[0], other_powers[0])
            for power in self_powers + other_powers:
                if denom == 1:
                    break

                denom = gcd(power, denom)

            small_self  = self
            small_other = other

            if denom > 1:
                small_self  = small_self.map_coeffs(lambda idx, val: (idx // denom, val))
                small_other = small_other.map_coeffs(lambda idx, val: (idx // denom, val))


            # Shit polys to lowest power
            self_smallest_pow  = small_self.coeffs.values.keys()[0]
            other_smallest_pow = small_other.coeffs.values.keys()[0]

            small_self  = small_self >> self_smallest_pow
            small_other = small_other >> other_smallest_pow


            # Convolve and reconstruct
            poly = self._create_poly(_convolution(small_self.coeffs, small_other.coeffs)) << (self_smallest_pow+other_smallest_pow)

            if denom > 1:
                poly.coeffs = poly.coeffs.map(lambda idx, val: (idx*denom, val))

        return poly


    def __rmul__(self, other: int) -> 'Polynomial':
        return self * other


    def __neg__(self) -> object:
        return self._create_poly([(idx, -coeff) for idx, coeff in self.coeffs])


    def __truediv__(self, other: 'Polynomial') -> 'Polynomial':
        return self.__divmod__(other)[0]


    __floordiv__ = __truediv__


    def __mod__(self, other: 'Polynomial') -> 'Polynomial':
        return self.__divmod__(other)[1]


    def __pow__(self, exponent: int) -> 'Polynomial':
        return square_and_mul(self, exponent, self.ring.one)


    def __int__(self) -> int:
        from samson.math.general import poly_to_int
        return poly_to_int(self)


    def __eq__(self, other: 'Polynomial') -> bool:
        return type(self) == type(other) and self.coeffs == other.coeffs


    def __lt__(self, other: 'Polynomial') -> bool:
        if self.degree() < other.degree():
            return True

        elif self.degree() > other.degree():
            return False
        
        for idx, coeff in self.coeffs.values.items()[::-1]:
            other_coeff = other.coeffs[idx]

            if other_coeff != coeff:
                return coeff < other_coeff

        return False


    def __gt__(self, other: 'Polynomial') -> bool:
        return self != other and not self < other


    def __bool__(self) -> bool:
        return self.coeffs != self._create_sparse([self.coeff_ring.zero])


    def __lshift__(self, num: int):
        return self._create_poly(self._create_sparse([(idx+num, coeff) for idx, coeff in self.coeffs]))


    # Note: SparseVector automatically shifts the indices down to remain transparent with lists
    def __rshift__(self, num: int):
        return self._create_poly(self.coeffs[num:])


    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        return self != self.ring.zero and all([coeff.is_invertible() for _, coeff in self.coeffs])
