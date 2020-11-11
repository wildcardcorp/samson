from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import square_and_mul, gcd, kth_root, coppersmiths
from samson.math.factorization.general import factor as factor_int, pk_1_smallest_divisor
from samson.math.factorization.factors import Factors
from samson.math.sparse_vector import SparseVector
from samson.utilities.general import add_or_increment
from types import FunctionType
import itertools

class Polynomial(RingElement):

    def __init__(self, coeffs: list, coeff_ring: Ring=None, symbol: object=None, ring: Ring=None):
        """
        Parameters:
            coeffs     (list): Coefficients of the polynomial as a list of increasing degree or an expression.
            coeff_ring (Ring): Ring the coefficients are in.
            symbol   (Symbol): Symbol to use as the indeterminate.
            ring       (Ring): Parent PolynomialRing.
        """
        from samson.math.symbols import Symbol

        self.coeff_ring = coeff_ring
        c_type = type(coeffs)

        if c_type in [list, tuple, dict]:
            if c_type is dict or (len(coeffs) > 0 and type(coeffs[0]) is tuple):
                vec = coeffs

                if not self.coeff_ring:
                    if c_type is dict:
                        self.coeff_ring = list(coeffs.values())[0].ring
                    else:
                        self.coeff_ring = coeffs[0][1].ring

            else:
                if not self.coeff_ring:
                    self.coeff_ring = coeffs[0].ring

                vec = [self.coeff_ring.coerce(coeff) for coeff in coeffs]

            self.coeffs = self._create_sparse(vec)

        elif c_type is SparseVector:
            if not self.coeff_ring:
                self.coeff_ring = list(coeffs.values.values())[0].ring

            self.coeffs = coeffs

        else:
            raise TypeError(f"'coeffs' is not of an accepted type. Received {type(coeffs)}")


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


    def __iter__(self):
        for i in range(self.degree()+1):
            yield self[i]


    def __getitem__(self, idx: int) -> object:
        vec = self.coeffs[idx]
        if type(vec) is SparseVector:
            return self._create_poly(vec)
        else:
            return vec


    def __setitem__(self, idx: int, value: 'RingElement'):
        self.coeffs[idx] = value


    def __getstate__(self):
        return {'coeffs': self.coeffs, 'symbol_repr': self.symbol.repr}


    def __setstate__(self, state):
        from samson.math.symbols import Symbol
        o = Polynomial(state['coeffs'], symbol=Symbol(state['symbol_repr']))
        self.coeffs     = o.coeffs
        self.coeff_ring = o.coeff_ring
        self.ring       = o.ring
        self.symbol     = o.symbol

        #self.symbol.build(self.ring)



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
        total    = self.coeff_ring.zero
        last_idx = coeffs.last()

        for idx, c in coeffs.values.items()[::-1]:
            total *= x**(last_idx-idx)
            total += c
            last_idx = idx


        total *= x**idx

        return total


    def newton(self, x0, max_tries: int=10000):
        df    = self.derivative()
        tries = 0

        while tries < max_tries:
            a = self(x0)
            b = df(x0)

            if not a or not b:
                break

            a_b = a // b

            if not a_b:
                break

            x0 -= a_b
            tries += 1

        return x0


    def roots(self, **factor_kwargs) -> list:
        """
        Finds the roots of the polynomial (i.e. where the evaluation is zero).

        Parameters:
            factor_kwargs (kwargs): Keyword arguments to pass into factorization.

        Returns:
            list: List of roots.
        
        References:
            https://crypto.stanford.edu/pbc/notes/numbertheory/poly.html
            https://math.stackexchange.com/questions/170128/roots-of-a-polynomial-mod-n
        """
        from samson.math.algebra.rings.integer_ring import ZZ

        R = self.coeff_ring
        is_field = R.is_field()

        if is_field or R == ZZ:
            if is_field and self.degree() == 1:
                return [-self.monic()[0]]

            facs = self.factor(**factor_kwargs)
            return [-fac.monic().coeffs[0] for fac in facs.keys() if fac.degree() == 1]

        else:
            from samson.math.general import crt

            all_facs = []
            q_facs   = R.quotient.factor()
            for fac in q_facs:
                sub_facs = self.peel_coeffs().change_ring(R.ring/R.ring(fac)).factor(**factor_kwargs)
                all_facs.append([-sub_fac.coeffs[0] for sub_fac in sub_facs.keys() if sub_fac.degree() == 1])

            return [R(crt(comb)[0]) for comb in itertools.product(*all_facs)]


    def small_roots(self) -> list:
        """
        Finds small roots of a polynomial in `ZZ`/`ZZ`(`N`) using Coppersmith's method.

        Returns:
            list: List of roots.
        """
        from samson.math.algebra.rings.integer_ring import ZZ
        return coppersmiths(self.coeff_ring.characteristic, self.change_ring(ZZ))



    def companion_matrix(self) -> 'Matrix':
        """
        Generates its companion matrix.

        Returns:
            Matrix: Companion matrix.

        Examples:
            >>> from samson.math.algebra.rings.integer_ring import ZZ
            >>> from samson.math.symbols import Symbol
            >>> x = Symbol('x')
            >>> _ = ZZ[x]
            >>> f = x**3 -2*x**2 -5*x + 6
            >>> f.companion_matrix()
            <Matrix: rows=
            [ 0,  1,  0]
            [ 0,  0,  1]
            [ 6, -5, -2]>

        References:
            https://en.wikipedia.org/wiki/Companion_matrix

        """
        from samson.math.matrix import Matrix

        d = self.degree()-1
        R = self.coeff_ring

        M = Matrix.identity(d, R)
        c = Matrix.fill(R.zero, d, 1)
        M = c.row_join(M)

        return M.col_join(Matrix([list(self)[:-1]]))


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


    def derivative(self, n: int=1) -> 'Polynomial':
        """
        Returns the derivative of the Polynomial.

        Returns:
            Polynomial: Derivative of self.
        """
        if n <= 0:
            return self
        else:
            return self._create_poly([(idx-1, coeff * idx) for idx, coeff in self.coeffs if idx != 0]).derivative(n-1)


    def trunc_kth_root(self, k: int) -> 'Polynomial':
        """
        Calculates an inexact `k`-th root.

        Parameters:
            k (int): Root to take.
        
        Returns:
            Polynomial: `k`-th root.
        
        Examples:
            >>> from samson.math.algebra.rings.integer_ring import ZZ
            >>> from samson.math.symbols import Symbol
            >>> x = Symbol('x')
            >>> ZZ[x](x**4 + 2*x**2).trunc_kth_root(2)
            <Polynomial: x**2 + 2*x, coeff_ring=ZZ>

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
            <Polynomial: 2*x**5 + x**4 + 2*x**2 + x + 1, coeff_ring=ZZ>

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
            >>> poly = -1*x**18 + x**7 + 3*x**3
            >>> poly.square_free_decomposition()
            {<Polynomial: x**15 + -1*x**4 + -3, coeff_ring=ZZ>: 1, <Polynomial: x, coeff_ring=ZZ>: 3}

        """
        is_field = self.coeff_ring.is_field()
        def cond_monic(poly):
            if is_field:
                return poly.monic()
            else:
                return poly // poly.content()

        f = cond_monic(self)
        c = cond_monic(gcd(f, cond_monic(f.derivative())))
        w = f // c

        factors = {}

        i = 1
        while w != self.ring.one:
            y = cond_monic(gcd(w, c))
            fac = cond_monic(w // y)

            if fac != self.ring.one:
                add_or_increment(factors, fac, i)

            w, c, i = y, c // y, i + 1

        if c != self.ring.one:
            if self.coeff_ring.characteristic:
                c = c.trunc_kth_root(self.coeff_ring.characteristic)

            new_facs = c.square_free_decomposition()
            for new_fac in new_facs:
                add_or_increment(factors, new_fac, self.coeff_ring.characteristic or 1)

        return factors

    sff = square_free_decomposition


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
                f_star //= g

            i += 1

        if f_star != self.ring.one:
            S.append((f_star, f_star.degree()))

        if not S:
            return [(f, 1)]
        else:
            return S


    ddf = distinct_degree_factorization

    def equal_degree_factorization(self, d: int, subgroup_divisor: int=None, user_stop_func: FunctionType=lambda S: False) -> list:
        """
        Factors a Polynomial into factors of equal degrees.

        Parameters:
            d                (int): Degree to factor into.
            subgroup_divisor (int): Smallest divisor of `order - 1`.
            user_stop_func  (func): A function that takes in (facs) and returns True if the user wants to stop factoring.

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

            # Finite fields must be in the form p^k where `p` is prime and `k` >= 1.
            # If `p` is an odd prime, then 2|p^k-1.
            # This follows since an odd number times an odd number (e.g. itself)
            # produces an odd number.

            # If p is 2, then things are a bit more complicated. Luckily for us,
            # it's very patterned.

            # If 2|k, then 3|p^k-1.
            # If 3|k, then 7|p^k-1.
            # If 5|k, then 31|p^k-1.

            # In other words, if `k` is composite, then factors of 2^k-1 include the factors of
            # 2^p_i-1 for where `p_i` represents a factor of `k`.
            if not subgroup_divisor:
                subgroup_divisor = pk_1_smallest_divisor(q)

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
            while len(S) < r and (not irreducibility_cache or not all([irreducibility_cache[poly] for poly in S])) and not user_stop_func(S):
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

                        u_gcd_g_u = u // gcd_g_u
                        S.extend([gcd_g_u, u_gcd_g_u])

                        # Cache irreducibility results
                        irreducibility_cache[gcd_g_u]   = gcd_g_u.is_irreducible()
                        irreducibility_cache[u_gcd_g_u] = u_gcd_g_u.is_irreducible()
        except KeyboardInterrupt:
            pass

        return S

    edf = equal_degree_factorization


    def is_irreducible(self) -> bool:
        """
        Determines if a Polynomial is irreducible over its ring.

        Returns:
            bool: Whether or not the Polynomial is irreducible over its ring.
        
        References:
            https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Rabin's_test_of_irreducibility
            https://github.com/sympy/sympy/blob/d1301c58be7ee4cd12fd28f1c5cd0b26322ed277/sympy/polys/galoistools.py
            https://en.wikipedia.org/wiki/Irreducible_polynomial#Over_the_integers_and_finite_field
            https://www.imomath.com/index.php?options=623&lmm=0#:~:text=Table%20of%20contents)-,Irreducibility,nonconstant%20polynomials%20with%20integer%20coefficients.&text=Every%20quadratic%20or%20cubic%20polynomial,3%E2%88%924x%2B1.
        """
        from samson.math.general import frobenius_map, frobenius_monomial_base, find_coprime, batch_gcd
        from samson.math.algebra.rings.integer_ring import ZZ

        n = self.degree()

        # Either constant or degree one
        if n <= 1:
            return True

        # Divisible by indeterminate
        if not self.coeffs[0]:
            return False

        one  = self.coeff_ring.one
        zero = self.coeff_ring.zero

        # Divisible by element
        if min(batch_gcd(self.coeffs.values.values())) > one:
            return False


        if self.coeff_ring == ZZ:
            poly = self
            if self.LC() < one:
                poly = -self

            coeff_zero = -poly.coeffs[0]

            # Poly's of form x**n - c
            if poly.coeffs.sparsity == 2:
                is_neg = coeff_zero < zero

                # There doesn't exist a square root of a negative number
                # (x**4+16).is_irreducible() == True
                if not n % 2 and is_neg:
                    return True

                # Check if a root exists of c0
                root = kth_root(abs(coeff_zero), n)
                if is_neg:
                    root = -root

                if root**n == coeff_zero:
                    # (x**4-16).is_irreducible() == False
                    if poly.LC() == one:
                        return False

                    # If LC is not one, then we have to check if that has a root
                    # whose exponent divides degree.
                    else:
                        for fac in ZZ(n).factor():
                            fac = int(fac)
                            # (9*x**4-16).is_irreducible() == False
                            if kth_root(poly.LC(), fac)**fac == poly.LC():
                                return False

                        # (3*x**4-16).is_irreducible() == True
                        return True


                else:
                    # Coeff zero is not a root of degree
                    # (x**4-15).is_irreducible() == True
                    return True


            # Eisenstein’s Criterion
            # NOTE: We use 'batch_gcd' to cut down on the factors we have to consider
            # and hopefully break apart large factors.
            p_facs = [g.factor() for g in batch_gcd(poly.coeffs.values.values()[:-1]) if g != ZZ.one]
            p_facs = sum(p_facs, Factors())
            for fac in p_facs:
                # p∣a0,a1,…,ak,p∤ak+1 and p2∤a0, where k = n-1
                if not sum([c % fac for c in poly.coeffs.values.values()[:-1]]):
                    if poly.LC() % fac and coeff_zero % (fac**2):
                        return True


            # If dealing with the integers, we can convert into FF.
            #   From Wikipedia:
            #   "The irreducibility of a polynomial over the integers Z
            #   is related to that over the field F_p of `p` elements
            #   (for a prime `p`). In particular, if a univariate polynomial `f` over Z
            #   is irreducible over F_p for some prime `p` that does not
            #   divide the leading coefficient of `f` (the coefficient of the highest power of the variable),
            #   then f is irreducible over Z."

            # WARNING: This proves a poly over ZZ is irreducible if it's irreducible in F_p.
            # The converse is NOT true. This may say a poly over ZZ is reducible when it is not.
            lc = int(poly.LC())
            p  = 2

            if lc != 1:
                p = find_coprime(lc, range(2, lc**2))

            field = ZZ/ZZ(p)
            poly  = poly.change_ring(field)
        else:
            poly = self


        if not poly.coeff_ring.is_field():
            raise NotImplementedError("Irreducibility tests of polynomials over rings of composite characteristic is not implemented")

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


    def content(self) -> RingElement:
        """
        Returns:
            RingElement: The content (i.e. GCD of the coefficients).
        """
        vals = list(self.coeffs.values.values())
        content = vals[0]
        for val in vals[1:]:
            content = content.gcd(val)

        return content


    def _fac_ZZ(self, d: int=1, subgroup_divisor: int=None, user_stop_func: FunctionType=lambda S: False):
        """
        Performs factorization over ZZ. Assumes `self` is square-free.

        Internal use.

        Examples:
            >>> from samson.math.all import ZZ, Symbol
            >>> x = Symbol('x')
            >>> P = ZZ[x]
            >>> p = 1296*x**3 + 3654*x**2 + 3195*x + 812
            >>> p.factor().recombine() == p
            True

            >>> p = (x+5)*(3*x-7)*(x**4+1)
            >>> p.factor().recombine() == p
            True

        References:
            https://en.wikipedia.org/wiki/Factorization_of_polynomials#Factoring_univariate_polynomials_over_the_integers
        """
        from samson.math.general import next_prime
        from samson.math.algebra.rings.integer_ring import ZZ

        # 'f' must be content-free
        f = self // self.content()

        # Select a prime such that `p` > 2B
        # NOTE: Originally, the algorithm calls for a Hensel lift such that `p^a > 2B`.
        # We're just cheating ;)
        max_elem = max([abs(val) for val in f.coeffs.values.values()])
        p = max_elem.val*2

        # Find a `p` such that `g` is square-free
        while True:
            p = next_prime(p+1)
            R = ZZ/ZZ(p)
            g = f.change_ring(R)
            if sum(g.sff().values()) == 1:
                break

        # Factor over mod `p`
        facs = g.factor(d=d, subgroup_divisor=subgroup_divisor, user_stop_func=user_stop_func)

        # Here we "reattach" coefficients that were stripped due to monicity constraints of Cantor-Zassenhaus.
        # EXAMPLE: 1296*x**3 + 3654*x**2 + 3195*x + 812
        # The correct factorization is (6*x + 7) * (9*x + 4) * (24*x + 29)
        # However, it actually factors to (x + 2133) * (x + 6092) * (x + 4061) over ZZ/ZZ(7309)
        # Note that 24*(x + 2133) == (24*x + 29)
        d1_cands = []
        lc_facs  = f.LC().factor()
        for d in lc_facs.all_divisors():
            coeff = int(d)

            for poly in facs:
                cand = poly * coeff
                d1_cands.extend([cand, -cand])

        d1_cands = set(d1_cands)
        factors  = []

        # Test direct candidacy
        for fac in d1_cands:
            poss = fac.peel_coeffs()

            for cand in [poss, poss-p]:
                cand //= cand.content()

                while not f % cand:
                    f //= cand
                    factors.append(cand)

                    if f.is_irreducible():
                        factors.append(f)
                        return factors


        # Reassemble and reduce
        for canda, candb in itertools.permutations(d1_cands, 2):
            poss = (canda * candb).peel_coeffs()
            while not f % poss:
                f //= poss
                factors.append(poss)

                if f.is_irreducible():
                    break

        factors.append(f)
        return factors



    def factor(self, d: int=1, subgroup_divisor: int=None, user_stop_func: FunctionType=lambda S: False) -> list:
        """
        Factors the Polynomial into its constituent, irreducible factors.

        Parameters:
            d                (int): Degree to factor into.
            subgroup_divisor (int): Smallest divisor of `order - 1`.
            user_stop_func  (func): A function that takes in (facs) and returns True if the user wants to stop factoring.

        Returns:
            list: Factors.

        Examples:
            >>> from samson.math.algebra.all import *
            >>> from samson.math.symbols import Symbol
            >>> from functools import reduce
            >>> x  = Symbol('x')
            >>> Z7 = ZZ/ZZ(7)
            >>> P  = Z7[x]
            >>> #___________________
            >>> # Generate random factors
            >>> factors = [fac for fac in [P.random(P(x**3)) for _ in range(4)] if fac]
            >>> p = reduce(Polynomial.__mul__, factors, P[1]) # Build the Polynomial
            >>> reduce(Polynomial.__mul__, [fac**exp for fac, exp in p.factor().items()], P[1]) == p.monic() # Check the factorization is right
            True

        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.all import QQ, Symbol
        from samson.math.factorization.factors import Factors

        p = self
        if not p:
            return Factors({p:1})

        factors = Factors()

        # Add content as constant polynomial
        content = p.content()

        if content != self.coeff_ring.one:
            factors[self.ring(content)] = 1


        # If there isn't a constant, we can factor out
        # `x` until there is
        first_idx = list(p.coeffs.values.keys())[0]
        if first_idx:
            factors[p.symbol*1] = first_idx
            p >>= first_idx


        # Check for known irreducibles
        if p.degree() == 1:
            factors[p // content] = 1
            return factors

        if not p.degree():
            return factors


        if self.coeff_ring == ZZ:
            f    = p // content
            facs = [(poly._fac_ZZ(user_stop_func=user_stop_func), num) for poly, num in f.sff().items() if poly.degree()]

            for partial_factors, num in facs:
                for factor in partial_factors:
                    if factor != p.ring.one:
                        factor.symbol = p.symbol
                        add_or_increment(factors, factor, num)


        elif self.coeff_ring == QQ:
            # Strip off content
            # This will give `p` integer coefficients
            q = p // content

            # Factor `p` over ZZ
            P    = ZZ[Symbol(q.symbol.repr)]
            z    = P(q.coeffs.map(lambda idx, val: (idx, val.numerator)))
            facs = z.factor(d=d, subgroup_divisor=subgroup_divisor, user_stop_func=user_stop_func)

            # Coerce the factors back into QQ
            for fac, e in facs.items():
                fac = fac.change_ring(QQ)
                fac.symbol = q.symbol
                factors[fac] = e

        else:
            # Cantor-Zassenhaus (SFF -> DDF -> EDF)
            distinct_degrees = [(factor, num) for poly, num in p.sff().items() for factor in poly.ddf()]
            for (poly, _), num in distinct_degrees:
                for factor in poly.edf(d, subgroup_divisor=subgroup_divisor, user_stop_func=user_stop_func):
                    if factor != p.ring.one:
                        add_or_increment(factors, factor, num)

                        if user_stop_func(factors.keys()):
                            return factors

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


    def change_ring(self, ring: Ring) -> 'Polynomial':
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
            >>> p.change_ring(ZZ/ZZ(2))
            <Polynomial: x**4 + x**2 + 1, coeff_ring=ZZ/ZZ(2)>

        """
        return Polynomial({idx: ring(coeff) for idx, coeff in self.coeffs}, coeff_ring=ring)


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
            <Polynomial: x**4 + x**2 + 1, coeff_ring=ZZ>

        """
        return Polynomial({idx: coeff.val for idx, coeff in self.coeffs}, coeff_ring=self.coeff_ring.ring)


    def __divmod__(self, other: 'Polynomial') -> ('Polynomial', 'Polynomial'):
        """
        Examples:
            >>> from samson.math.all import Polynomial, ZZ, Symbol
            >>> R = ZZ/ZZ(127)
            >>> y = Symbol('y')
            >>> Q = R[y]
            >>> a = 94*y**9 + 115*y**8 + 4*y**7 + 14*y**6 + 14*y**5 + 111*y**4 + 76*y**3 + 47*y**2 + 124*y + 11
            >>> b = 92*y**4 + 93*y**3 + 76*y**2 + 62*y + 101
            >>> divmod(a,b)
            (<Polynomial: 59*y**5 + 41*y**4 + 41*y**3 + 88*y**2 + 90*y + 110, coeff_ring=ZZ/ZZ(127)>, <Polynomial: 79*y**3 + 79*y**2 + 89*y + 77, coeff_ring=ZZ/ZZ(127)>)

            >>> x = Symbol('x')
            >>> P = ZZ[x]
            >>> p = 9*x**10 + 24*x**9 - 105*x**8 - 6*x**6 - 16*x**5 + 70*x**4 - 3*x**2 - 8*x + 35
            >>> d = 100*x
            >>> divmod(p,d)
            (<Polynomial: -2*x**7, coeff_ring=ZZ>, <Polynomial: 9*x**10 + 24*x**9 + 95*x**8 + -6*x**6 + -16*x**5 + 70*x**4 + -3*x**2 + -8*x + 35, coeff_ring=ZZ>)

        """
        # Check for zero
        other = self.ring.coerce(other)
        if not other:
            raise ZeroDivisionError

        # Divisor > dividend, early out
        n = other.degree()
        if n > self.degree():
            return self.ring.zero, self

        q = self.ring.zero
        r = self

        remainder = self._create_sparse([0])
        is_field  = self.coeff_ring.is_field()

        zero, one = self.coeff_ring.zero, self.coeff_ring.one

        while r and r.degree() >= n:
            r_start = r
            # Fields have exact division, but we have to
            # keep track of remainders for non-trivial Euclidean division
            if is_field:
                t, rem = r.LC() / other.LC(), zero
            else:
                t, rem = divmod(r.LC(), other.LC())

                # Handle -1 specifically!
                # This means it doesn't ACTUALLY divide it
                if t == -one and rem > zero:
                    t, rem = zero, r.LC()


            r -= (other << (r.degree() - n)) * t
            remainder[r.degree()] = rem

            if not t:
                r.coeffs[r.degree()] = t

            # Update q
            q  += t
            q <<= r_start.degree() - r.degree()


        r_deg = r.degree()
        r     = self.ring(remainder) + self.ring(r.coeffs[:n])

        if q:
            q >>= (n-r_deg)

        return q, r


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
        if gmul is not None:
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


    def __floordiv__(self, other: 'Polynomial') -> 'Polynomial':
        return self.__divmod__(other)[0]


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

        keys = set(self.coeffs.values.keys()).union(other.coeffs.values.keys())

        for idx in keys:
            coeff       = self.coeffs[idx]
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



    def gcd(self, other: 'Polynomial', use_naive: bool=False) -> 'Polynomial':
        """
        References:
            https://math.stackexchange.com/a/2587365
        """
        from samson.math.algebra.fields.fraction_field import FractionField

        # Euclidean division is only defined for polynomials over a field
        R = self.coeff_ring
        if R.is_field():
            return super().gcd(other)

        elif use_naive:
            # Assumes invertibility despite not being a field
            # We use monic to reduce the leading coefficient so the algorithm will terminate
            a, b = self, other
            while b:
                a = a.monic()
                b = b.monic()
                a, b = b, a % b
            return a.monic()

        else:
            # Embed ring into a fraction field
            Q   = FractionField(R)
            s_q = self.change_ring(Q)
            o_q = other.change_ring(Q)

            fac = s_q.gcd(o_q)
            c   = fac.content()

            result = s_q.content().gcd(o_q.content())*(fac // c)
            return self.ring(result.coeffs.map(lambda idx, val: (idx, val.numerator)))
