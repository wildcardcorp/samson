from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.general import square_and_mul, gcd, kth_root, coppersmiths, product
from samson.math.factorization.general import factor as factor_int, pk_1_smallest_divisor
from samson.math.factorization.factors import Factors
from samson.math.sparse_vector import SparseVector
from samson.auxiliary.theme import POLY_COLOR_WHEEL, color_format
from samson.math.fft.karatsuba import karatsuba
from samson.utilities.general import add_or_increment
from samson.utilities.manipulation import get_blocks
from samson.utilities.runtime import RUNTIME
from types import FunctionType
import itertools

from samson.auxiliary.lazy_loader import LazyLoader
_integer_ring  = LazyLoader('_integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')
_symbol        = LazyLoader('_symbol', globals(), 'samson.math.symbols')


def _should_kronecker(n):
    b = n.bit_length()
    if b < 6:
        return 20
    elif b < 9:
        return 30
    elif b < 21:
        return 40
    elif b < 26:
        return 60
    elif b < 31:
        return 80
    else:
        return _symbol.oo
    

class Polynomial(RingElement):

    def __init__(self, coeffs: list, coeff_ring: Ring=None, symbol: object=None, ring: Ring=None):
        """
        Parameters:
            coeffs     (list): Coefficients of the polynomial as a list of increasing degree or an expression.
            coeff_ring (Ring): Ring the coefficients are in.
            symbol   (Symbol): Symbol to use as the indeterminate.
            ring       (Ring): Parent PolynomialRing.
        """
        Symbol = _symbol.Symbol

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
        super().__init__(ring or self.coeff_ring[self.symbol])
        self.coeffs.trim()

        if len(self.coeffs.values) == 0:
            self.coeffs = self._create_sparse([self.coeff_ring.zero])



    def shorthand(self, tinyhand: bool=False, idx_mod: int=0) -> str:
        poly_repr = []

        if self.LC():
            idx_color = POLY_COLOR_WHEEL[self.coeff_ring.structure_depth()-1 % len(POLY_COLOR_WHEEL)]

            for idx, coeff in self.coeffs.values.items():
                idx += idx_mod

                # Skip zero coeffs unless the poly is zero
                if coeff == coeff.ring.zero and not len(self.coeffs) == 1:
                    continue

                # Remove implicit ones
                if coeff == coeff.ring.one and idx != 0:
                    coeff_short_mul = ''
                else:
                    if tinyhand:
                        shorthand = coeff.tinyhand()
                    else:
                        shorthand = coeff.shorthand()

                    if idx != 0:
                        shorthand = f'({shorthand})'

                    coeff_short_mul = shorthand + '*'

                # Handle special indices
                if idx == 0:
                    full_coeff = f'{coeff_short_mul[:-1]}'
                elif idx == 1:
                    full_coeff = f'{coeff_short_mul}{self.symbol}'
                else:
                    full_coeff = f'{coeff_short_mul}{self.symbol}{RUNTIME.poly_exp_separator}{color_format(idx_color, idx)}'

                poly_repr.append(full_coeff)

            return ' + '.join(poly_repr[::-1])
        else:
            return self.coeff_ring.zero.shorthand()



    def tinyhand(self) -> str:
        return self.shorthand(True)


    def __reprdir__(self):
        return ['__raw__', 'coeff_ring']


    @property
    def __raw__(self):
        return str(self)


    def __str__(self):
        from samson.utilities.runtime import RUNTIME
        return RUNTIME.default_short_printer(self)


    def __call__(self, val: RingElement=None, **kwargs) -> RingElement:
        return self.evaluate(val, **kwargs)


    def __hash__(self) -> int:
        return hash((self.coeff_ring, self.coeffs, self.__class__))


    def __iter__(self):
        for i in range(self.degree()+1):
            yield self[i]
    

    def __len__(self):
        return self.degree()+1


    def __getitem__(self, idx: int) -> object:
        vec = self.coeffs[idx]
        if type(vec) is SparseVector:
            return self._create_poly(vec)
        else:
            return vec


    def __setitem__(self, idx: int, value: 'RingElement'):
        self.coeffs[idx] = value


    def __getstate__(self):
        return {'coeffs': self.coeffs, 'coeff_ring': self.coeff_ring, 'symbol_repr': self.symbol.repr}


    def __setstate__(self, state):
        Symbol = _symbol.Symbol
        o = Polynomial(state['coeffs'], state['coeff_ring'], symbol=Symbol(state['symbol_repr']))
        self.coeffs     = o.coeffs
        self.coeff_ring = o.coeff_ring
        self.ring       = o.ring
        self.symbol     = o.symbol


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


    def LT(self) -> RingElement:
        """
        Returns the leading term.

        Returns:
            RingElement: Term of the highest degree.
        """
        try:
            return self.LC()*self.LM()
        except IndexError:
            return self.coeff_ring.zero



    def LM(self) -> RingElement:
        """
        Returns the leading monomial.

        Returns:
            RingElement: Monomial of the highest degree.
        """
        try:
            return self.symbol**(self.degree())
        except IndexError:
            return self.coeff_ring.zero


    def evaluate(self, val: RingElement=None, **kwargs) -> RingElement:
        """
        Evaluates the `Polynomial` at `val` using Horner's method.

        Parameters:
            val (RingElement): Point to evaluate at.

        Returns:
            RingElement: Evaluation at `val`.
        """
        if val is not None:
            x = val
            if not self.degree():
                return self[0]

            coeffs   = self.coeffs
            total    = self.coeff_ring.zero
            last_idx = coeffs.last()

            for idx, c in coeffs.values.items()[::-1]:
                total *= x**(last_idx-idx)
                total += c
                last_idx = idx


            total *= x**idx

            return total

        elif kwargs:
            if self.symbol.repr in kwargs:
                passed_kwargs = {k: v for k,v in kwargs.items() if k != self.symbol.repr}
                self_eval     = self(kwargs[self.symbol.repr])

                if passed_kwargs:
                    self_eval = self_eval(**passed_kwargs)
                return self_eval

            else:
                return self._create_poly({idx: coeff(**kwargs) for idx, coeff in self.coeffs.values.items()})

        else:
            raise ValueError('Either "val" or "kwargs" must be specified')



    def modular_composition(self, h, mod):
        """
        Evaluates the `Polynomial` at `val` using Horner's method.

        Parameters:
            val (RingElement): Point to evaluate at.

        Returns:
            RingElement: Evaluation at `val`.
        """
        x = h % mod
        if not self.degree():
            return self[0]

        coeffs   = self.coeffs
        total    = self.coeff_ring.zero
        last_idx = coeffs.last()

        for idx, c in coeffs.values.items()[::-1]:
            total *= x**(last_idx-idx)
            total += c
            total %= mod
            last_idx = idx


        total *= x**idx

        return total % mod



    def reverse(self) -> 'Polynomial':
        n = self.degree()
        return self._create_poly({n-idx: c for idx, c in self.coeffs.values.items()})


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

        return self.coeff_ring(x0)


    def roots(self, use_hensel: bool=False, **factor_kwargs) -> list:
        """
        Finds the roots of the polynomial (i.e. where the evaluation is zero).

        Parameters:
            factor_kwargs (kwargs): Keyword arguments to pass into factorization.
            use_hensel      (bool): Uses Hensel lifting instead of congruences. Much fast for very large moduli but isn't guaranteed to find all roots.

        Returns:
            list: List of roots.

        References:
            https://crypto.stanford.edu/pbc/notes/numbertheory/poly.html
            https://math.stackexchange.com/questions/170128/roots-of-a-polynomial-mod-n
        """
        ZZ = _integer_ring.ZZ
        from samson.math.algebra.rings.padic_integers import Zp
        from samson.math.algebra.rings.padic_numbers import PAdicNumberField
        from samson.math.symbols import oo

        R = self.coeff_ring
        is_field = R.is_field()


        if type(R) in [Zp, PAdicNumberField]:
            roots = self.change_ring(ZZ).hensel_lift(R.p, R.prec, use_padic=True, use_number_field=type(R) == PAdicNumberField)
            return [r for r in roots if not self(r)]


        elif is_field or R == ZZ:
            if is_field and self.degree() == 1:
                return [-self.monic()[0]]

            facs = self.factor(**factor_kwargs)
            return [-fac.monic().coeffs[0] for fac in facs.keys() if fac.degree() == 1]


        elif R.order() != oo:
            from samson.math.general import crt

            all_facs = []
            results  = []
            q_facs   = R.quotient.factor()

            if use_hensel or len(q_facs) == 1:
                for fac, e in q_facs.items():
                    Q      = ZZ/ZZ(fac**e)
                    nroots = [Q(r) for r in self.change_ring(ZZ).hensel_lift(fac, e, use_padic=False)]
                    if nroots:
                        all_facs.append(nroots)

                if all_facs:
                    for comb in itertools.product(*[f for f in all_facs if f]):
                        root = R(crt(comb)[0])

                        if not self(root):
                            results.append(root)

            else:
                P = int(product(q_facs))

                for fac in q_facs:
                    nroots = self.change_ring(ZZ/fac).roots()
                    if nroots:
                        all_facs.append(nroots)


                if all_facs:
                    for comb in itertools.product(*all_facs):
                        candidate = R(crt(comb)[0])

                        # Essentially Hensel lifting
                        for _ in range(int(R.quotient) // P):
                            if not self(candidate):
                                results.append(candidate)
                            candidate += P

            return results
        
        else:
            raise NotImplementedError(f"Polynomial factorization not implemented over {R}")


    def small_roots(self) -> list:
        """
        Finds small roots of a polynomial in `ZZ`/`ZZ`(`N`) using Coppersmith's method.

        Returns:
            list: List of roots.
        """
        ZZ = _integer_ring.ZZ
        return coppersmiths(self.coeff_ring.characteristic(), self.change_ring(ZZ))



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
            <Matrix: coeff_ring=ZZ, num_rows=3, num_cols=3, 
               0   1   2
            0 [0,  1,  0]
            1 [0,  0,  1]
            2 [6, -5, -2]>


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
        return self.coeffs.values.keys()[0] if self else 0



    def hensel_lift(self, p: int, k: int, last_roots: list=None, use_padic: bool=False, use_number_field: bool=False) -> list:
        """
        Finds roots in `ZZ/ZZ(p**k)` where `p` is the coefficient ring's characteristic.

        Parameters:
            p (int): Prime modulus to find roots in.
            k (int): Power to lift to.

        Returns:
            list: Lifted roots.

        References:
            https://en.wikipedia.org/wiki/Hensel%27s_lemma
        """
        ZZ = _integer_ring.ZZ
        from samson.math.algebra.rings.padic_integers import Zp

        if not ZZ(p).is_prime():
            raise ValueError("'p' must be prime")

        if not k:
            return []


        roots = last_roots or self.change_ring(ZZ/ZZ(p)).roots()
        for e in range(k if last_roots else 2, k+1):
            R = Zp(p, e)

            if use_number_field:
                R = R.fraction_field()

            f      = self.change_ring(R)
            df     = f.derivative()
            nroots = []

            for root in roots:
                zroot = ZZ(root)

                if not use_padic and f(zroot):
                    continue

                dfr = df(zroot)

                if (use_padic and dfr) or (not use_padic and dfr % p):
                    s = -f(zroot)/dfr + zroot
                    nroots.append(s)
                else:
                    for t in range(int(p)):
                        nroots.append(R(zroot) + R(t)*p**(e-1))

            roots = nroots

        return roots



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

        Parameter:
            n (int): Number of times to take derivative.

        Returns:
            Polynomial: Derivative of self.
        """
        if n <= 0:
            return self
        else:
            return self._create_poly([(idx-1, coeff * idx) for idx, coeff in self.coeffs if idx != 0]).derivative(n-1)


    def integral(self, n: int=1) -> 'Polynomial':
        """
        Returns the integral of the Polynomial.

        Parameter:
            n (int): Number of times to take integral.

        Returns:
            Polynomial: Integral of self.
        """
        if n <= 0:
            return self
        else:
            return self._create_poly([(idx+1, coeff/(idx+1)) for idx, coeff in self.coeffs]).derivative(n-1)


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
            <Polynomial: x^2 + (2)*x, coeff_ring=ZZ>

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
            <Polynomial: (2)*x^5 + x^4 + (2)*x^2 + x + 1, coeff_ring=ZZ>

        """
        return self._create_poly([(idx, coeff % mod) for idx, coeff in self.coeffs])


    def _yun_sff(self):
        """
        Yun's square-free factorization for characteristic zero integral domains.

        References:
            https://en.wikipedia.org/wiki/Square-free_polynomial#Yun's_algorithm
        """
        assert self.coeff_ring.characteristic() == 0
        
        f  = self
        fp = self.derivative()

        a0 = gcd(f, fp)
        bi = f // a0
        ci = fp // a0
        di = ci - bi

        facs = []
        while bi.degree():
            ai = gcd(bi, di)
            bi = bi // ai
            ci = di // ai
            di = ci - bi.derivative()
            facs.append(ai)

        polys = [fac for fac in facs if fac.degree()]
        f     = self

        factors = Factors()
        for poly in polys:
            while True:
                q, r = divmod(f, poly)
                if r:
                    break

                factors.add(poly)
                f = q

        return factors


    def square_free_decomposition(self) -> Factors:
        """
        Decomposes a Polynomial into its square-free factors. Used as the first step in factorization.

        Returns:
            Factors: Square-free factors of self.

        Examples:
            >>> from samson.math.all import Polynomial, ZZ
            >>> from samson.math.symbols import Symbol
            >>> x = Symbol('x')
            >>> _ = ZZ[x]
            >>> poly = -1*x**18 + x**7 + 3*x**3
            >>> poly.square_free_decomposition()
            <Factors: factors=SortedDict({<Polynomial: x, coeff_ring=ZZ>: 3, <Polynomial: x^15 + (-1)*x^4 + -3, coeff_ring=ZZ>: 1})>

        References:
            https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization
        """
        if not self.coeff_ring.characteristic():
            return self._yun_sff()

        is_field = self.coeff_ring.is_field()
        def cond_monic(poly):
            if is_field:
                return poly.monic()
            else:
                return poly // poly.content()

        f = cond_monic(self)
        c = cond_monic(gcd(f, cond_monic(f.derivative())))
        w = f // c

        factors = Factors()

        i = 1
        while w != self.ring.one:
            y   = cond_monic(gcd(w, c))
            fac = cond_monic(w // y)

            if fac != self.ring.one:
                factors.add(fac, i)

            w, c, i = y, c // y, i + 1

        if c != self.ring.one:
            if self.coeff_ring.characteristic():
                c = c.trunc_kth_root(self.coeff_ring.characteristic())

            new_facs = c.square_free_decomposition()
            for new_fac in new_facs:
                factors.add(new_fac, self.coeff_ring.characteristic() or 1)

        return factors

    sff = square_free_decomposition


    def distinct_degree_factorization(self) -> list:
        """
        Factors a Polynomial into factors of different degrees.

        Returns:
            list: Distinct-degree factors of self.
        
        References:
            https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization
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

        f_quot = f.ring / f
        if self.coeff_ring.order() != oo:
            q = self.coeff_ring.order()

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
        if self.coeff_ring.order() == oo:
            raise NotImplementedError('Currently can\'t factor polynomials in rings of infinite order')

        try:
            while len(S) < r and (not irreducibility_cache or not all([irreducibility_cache[poly] for poly in S])) and not user_stop_func(S):
                h = f.ring.random(f)
                g = gcd(h, f).monic()

                if g == one:
                    h = f_quot(h)
                    j = h
                    for _ in range(d-1):
                        j  = frobenius_map(j, f, bases=bases)
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


    def _is_irred_ZZ(self):
        from samson.math.general import find_coprime, batch_gcd
    
        ZZ   = _integer_ring.ZZ
        one  = self.coeff_ring.one
        zero = self.coeff_ring.zero
        n    = self.degree()

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
        facs = self._ZZ_to_lossless_Fp().factor()
        return sum(facs.values()) == 1 or all(self % fac.change_ring(ZZ) for fac in facs)


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
        from samson.math.general import frobenius_map, frobenius_monomial_base, batch_gcd
        ZZ = _integer_ring.ZZ

        n = self.degree()

        # Either constant or degree one
        if n <= 1:
            return True

        # Divisible by indeterminate
        if not self.coeffs[0]:
            return False

        one = self.coeff_ring.one

        # Divisible by element
        if min(batch_gcd(self.coeffs.values.values())) > one:
            return False


        if self.coeff_ring == ZZ:
            return self._is_irred_ZZ()


        if not self.coeff_ring.is_field():
            raise NotImplementedError("Irreducibility tests of polynomials over rings of composite characteristic is not implemented")

        x = self.symbol
        f = self.monic()
        P = self.ring

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


    def _ZZ_to_lossless_Fp(self):
        """
        Embeds a polynomial over ZZ into a field F_p such that a lossless factorization can occur.
        """
        from samson.math.general import next_prime
        ZZ = _integer_ring.ZZ

        assert self.coeff_ring == ZZ

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
                return g



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
        # from samson.math.general import next_prime
        # ZZ = _integer_ring.ZZ

        # 'f' must be content-free
        f = self // self.content()
        g = f._ZZ_to_lossless_Fp()
        p = g.coeff_ring.characteristic()

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
        ZZ = _integer_ring.ZZ
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
            <Polynomial: x^4 + x^2 + 1, coeff_ring=ZZ/(ZZ(2))>

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
            <Polynomial: x^4 + x^2 + 1, coeff_ring=ZZ>

        """
        return Polynomial({idx: coeff.val for idx, coeff in self.coeffs}, coeff_ring=self.coeff_ring.ring)


    def __elemdivmod__(self, other: 'Polynomial') -> ('Polynomial', 'Polynomial'):
        """
        Examples:
            >>> from samson.math.all import Polynomial, ZZ, Symbol
            >>> R = ZZ/ZZ(127)
            >>> y = Symbol('y')
            >>> Q = R[y]
            >>> a = 94*y**9 + 115*y**8 + 4*y**7 + 14*y**6 + 14*y**5 + 111*y**4 + 76*y**3 + 47*y**2 + 124*y + 11
            >>> b = 92*y**4 + 93*y**3 + 76*y**2 + 62*y + 101
            >>> divmod(a,b)
            (<Polynomial: (59)*y^5 + (41)*y^4 + (41)*y^3 + (88)*y^2 + (90)*y + 110, coeff_ring=ZZ/(ZZ(127))>, <Polynomial: (79)*y^3 + (79)*y^2 + (89)*y + 77, coeff_ring=ZZ/(ZZ(127))>)

            >>> x = Symbol('x')
            >>> P = ZZ[x]
            >>> p = 9*x**10 + 24*x**9 - 105*x**8 - 6*x**6 - 16*x**5 + 70*x**4 - 3*x**2 - 8*x + 35
            >>> d = 100*x
            >>> divmod(p,d)
            (<Polynomial: (-2)*x^7, coeff_ring=ZZ>, <Polynomial: (9)*x^10 + (24)*x^9 + (95)*x^8 + (-6)*x^6 + (-16)*x^5 + (70)*x^4 + (-3)*x^2 + (-8)*x + 35, coeff_ring=ZZ>)

        """
        # Check for zero
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

        if is_field:
            o_lc_inv  = ~other.LC()

        while r and r.degree() >= n:
            r_start = r
            # Fields have exact division, but we have to
            # keep track of remainders for non-trivial Euclidean division
            if is_field:
                t, rem = r.LC() * o_lc_inv, zero
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


    def _hensel_division(self, other: 'Polynomial') -> 'Polynomial':
        """
        Finds the quotient of `self` // `other` in O(`n`log`n`) time.

        References:
            "Algebra and Computation, Lecture 6" (http://people.csail.mit.edu/madhu/ST12/scribe/lect06.pdf)
        """
        Symbol = _symbol.Symbol

        f_hat  = self.reverse()
        g_hat  = other.reverse()
        T      = self.coeff_ring[[Symbol('y')]]
        n, m   = self.degree(), other.degree()
        T.prec = n-m+1
        res    = (T(f_hat)/T(g_hat)).val.reverse()
        return res << (n-m-res.degree())



    def __elemadd__(self, other: 'Polynomial') -> 'Polynomial':
        vec = self._create_sparse([])
        for idx, coeff in self.coeffs:
            vec[idx] = coeff + other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = coeff

        return self._create_poly(vec)


    def __elemsub__(self, other: 'Polynomial') -> 'Polynomial':
        vec = self._create_sparse([])
        for idx, coeff in self.coeffs:
            vec[idx] = coeff - other.coeffs[idx]

        for idx, coeff in other.coeffs:
            if not idx in self.coeffs:
                vec[idx] = -coeff

        return self._create_poly(vec)



    def __elemmul__(self, other: object) -> object:
        if self.ring.ring.__class__.__name__ == 'QuotientRing' and self.ring.ring.ring == _integer_ring.ZZ and self.degree() > _should_kronecker(self.ring.characteristic()):
            # Kronecker substitution for small ZZ/ZZ(n)
            return self._kronecker_substitution(other)

        elif not RUNTIME.poly_fft_heuristic(self, other):
            if self.ring.use_karatsuba:
                n, m = self.degree(), other.degree()

                if n and m:
                    # Fast heuristic for karatsuba
                    convolution_estimate = self.coeffs.sparsity*other.coeffs.sparsity
                    karatsuba_cutoff     = max(n, m)**1.58

                    if convolution_estimate > karatsuba_cutoff:
                        return karatsuba(self, other)

            # Naive convolution
            new_coeffs = {}

            for i, coeff_h in self.coeffs:
                for j, coeff_g in other.coeffs:
                    c = i+j
                    if c in new_coeffs:
                        new_coeffs[c] += coeff_h*coeff_g
                    else:
                        new_coeffs[c] = coeff_h*coeff_g


            poly = self._create_poly(self._create_sparse(new_coeffs))

        else:
            # FFT conv
            from samson.math.fft.gss import _convolution

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
            self_smallest_pow  = small_self.valuation()
            other_smallest_pow = small_other.valuation()

            small_self  = small_self >> self_smallest_pow
            small_other = small_other >> other_smallest_pow


            # Convolve and reconstruct
            poly = self._create_poly(_convolution(list(small_self), list(small_other))) << (self_smallest_pow+other_smallest_pow)

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
        return type(self) == type(other) and self.coeff_ring == other.coeff_ring and self.coeffs == other.coeffs


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


    def _kronecker_substitution(self, g):
        """
        References:
            https://math.mit.edu/classes/18.783/2015/LectureNotes3.pdf
        """
        ZZ = _integer_ring.ZZ

        f = self
        p = f.coeff_ring.characteristic()
        d = max(f.degree(), g.degree())
        n = 2*p.bit_length()+(d+1).bit_length()
        a = f.change_ring(ZZ)(2**n)
        b = g.change_ring(ZZ)(2**n)
        c = int(a*b)
        return self.ring([int(b[::-1], 2) % p for b in get_blocks(bin(c)[2:][::-1], n, True)])


    def cache_div(self, prec: int):
        from samson.math.poly_division_cache import PolyDivisionCache
        self.__div_cache = PolyDivisionCache(self, prec)
        self.__relemdivmod__ = self.__div_cache.__relemdivmod__
