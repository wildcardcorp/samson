from samson.math.general import fast_mul, square_and_mul, is_prime, pohlig_hellman, bsgs, pollards_rho_log, mod_inv, xlcm, gcd
from samson.math.factorization.general import factor
from samson.math.factorization.factors import Factors
from types import FunctionType
from samson.utilities.runtime import RUNTIME
from samson.auxiliary.lazy_loader import LazyLoader
from samson.utilities.exceptions import CoercionException, NotInvertibleException, NoSolutionException, SearchspaceExhaustedException
from samson.utilities.general import binary_search_unbounded, binary_search
from samson.core.base_object import BaseObject

_poly = LazyLoader('_poly', globals(), 'samson.math.polynomial')
_quot = LazyLoader('_quot', globals(), 'samson.math.algebra.rings.quotient_ring')
_frac = LazyLoader('_frac', globals(), 'samson.math.algebra.fields.fraction_field')
_symb = LazyLoader('_symb', globals(), 'samson.math.symbols')

def set_precendence_override(should_override):
    def _wrapper(func):
        func.has_precedence_override = should_override
        return func
    
    return _wrapper


class Ring(BaseObject):

    def order_factors(self):
        oo = _symb.oo

        if not hasattr(self, '_order_factor_cache'):
            self._order_factor_cache = None

        if not self._order_factor_cache and self.order() != oo:
            self._order_factor_cache = factor(self.order())

        return self._order_factor_cache


    def shorthand(self) -> str:
        pass


    def tinyhand(self) -> str:
        return ""


    def __str__(self):
        return self.shorthand()


    def structure_depth(self):
        if hasattr(self, 'ring'):
            return self.ring.structure_depth()+1
        else:
            return 1


    def is_superstructure_of(self, R: 'Ring') -> bool:
        """
        Determines whether `self` is a superstructure of `R`.

        Parameters:
            R (Ring): Possible substructure.

        Returns:
            bool: Whether `self` is a superstructure of `R`.
        """
        if hasattr(self, 'coeff_ring'):
            if self.coeff_ring == R:
                return True
            else:
                return self.coeff_ring.is_superstructure_of(R)


        elif hasattr(self, 'ring'):
            if self.ring == R:
                return True
            else:
                return self.ring.is_superstructure_of(R)

        return False



    def random(self, size: object) -> 'RingElement':
        """
        Generate a random element.

        Parameters:
            size (int/RingElement): The maximum ordinality/element (non-inclusive).

        Returns:
            RingElement: Random element of the algebra.
        """
        from samson.math.general import random_int

        if type(size) is int:
            return self[random_int(size)]
        else:
            return self[random_int(size.ordinality())]



    def fraction_field(self) -> 'Ring':
        """
        Returns:
            FractionField: A fraction field of self.
        """
        from samson.math.algebra.fields.fraction_field import FractionField
        return FractionField(self)


    def base_coerce(self, other: object) -> 'RingElement':
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            RingElement: Coerced element.
        """
        t_o = type(other)
        if t_o is _quot.QuotientElement and other.ring.ring == self:
            return other.val

        elif t_o is _frac.FractionFieldElement and other.ring.ring == self:
            scaled = other.numerator / other.denominator

            if scaled.ring == other.ring:
                raise CoercionException(self, other)
            else:
                return scaled

        else:
            return other


    def mul_group(self) -> 'MultiplicativeGroup':
        """
        Returns the `MultiplicativeGroup` of `self`.
        """
        from samson.math.algebra.rings.multiplicative_group import MultiplicativeGroup
        return MultiplicativeGroup(self)



    def __call__(self, args, **kwargs) -> 'RingElement':
        return self.coerce(self.base_coerce(args), **kwargs)


    def __contains__(self, element: 'RingElement') -> bool:
        try:
            self.coerce(element)
            return True
        except CoercionException:
            return False


    def element_at(self, x: int) -> 'RingElement':
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           RingElement: The `x`-th element.
        """
        raise NotImplementedError()


    def order(self) -> int:
        raise NotImplementedError()


    def isomorphisms(self) -> list:
        raise NotImplementedError()


    def find_gen(self) -> 'RingElement':
        """
        Finds a generator of the `Ring`.

        Returns:
            RingElement: A generator element.
        """
        oo = _symb.oo

        if self.order() == oo:
            return self.one


        return self.find_element_of_order(self.order())


    def find_element_of_order(self, n: int=None, n_facs: 'Factors'=None, allow_order_call: bool=True) -> 'RingElement':
        """
        Finds an element of order `n`.

        Parameters:
            n          (int): Size of the subgroup.
            n_facs (Factors): Factors of the size of the subgroup.

        Returns:
            RingElement: Element of order `n`.
        """
        if allow_order_call:
            if self.order() % n:
                raise ValueError(f"Ring order is not divisible by {n}. No element exists with this order.")

            max_order = None
            while True:
                elem = self.random()
                o    = elem.order()

                if elem:
                    if o % n:
                        # Merge elements to find elements of successively higher order
                        if max_order:
                            merged = max_order.merge(elem)
                            if not merged.order() % n:
                                return merged * (merged.order() // n)

                            max_order = merged
                        else:
                            max_order = elem
                    else:
                        return elem * (o // n)

        else:
            if not n_facs:
                n_facs = factor(n)

            while True:
                elem = self.random()
                if not n*elem and elem.find_maximum_subgroup(n=n, n_facs=n_facs) == n:
                    elem.order_cache = n
                    return elem


    def __truediv__(self, element: 'RingElement') -> 'QuotientRing':
        if element.ring != self:
            raise ValueError("'element' must be an element of the ring")

        return _quot.QuotientRing(element, self)


    def __getitem__(self, x: int) -> 'RingElement':
        type_x = type(x)
        if type_x.__name__ == 'Symbol' or type_x is tuple and type(x[0]).__name__ == 'Symbol':
            from samson.math.algebra.rings.polynomial_ring import PolynomialRing

            if type_x is tuple:
                ring = self
                for symbol in x:
                    ring = PolynomialRing(ring, symbol)

                return ring

            else:
                return PolynomialRing(self, x)

        elif type_x is list and type(x[0]).__name__ == 'Symbol':
            from samson.math.algebra.rings.power_series_ring import PowerSeriesRing
            return PowerSeriesRing(self, x[0])

        else:
            return self.element_at(x)


    def is_field(self) -> bool:
        oo = _symb.oo
        return self.order() != oo and is_prime(self.order())
    

    def frobenius_endomorphism(self) -> 'Map':
        from samson.math.map import Map
        p = self.characteristic()
        if not is_prime(p):
            raise ValueError(f'Characteristic of {self} not prime')
        return Map(domain=self, codomain=self, map_func=lambda r: self(r)**p)



class RingElement(BaseObject):

    def __init__(self, ring: Ring):
        self.ring = ring
        self.order_cache = None


    def __reprdir__(self):
        return list(self.__dict__.keys() - {'order_cache'})

    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}({str(self.val)})'


    def tinyhand(self) -> str:
        return f'{self.val.tinyhand()}'


    def __str__(self):
        return RUNTIME.default_short_printer(self)

    def __hash__(self) -> int:
        return hash((self.ring, self.val))


    def __elemadd__(self, other: 'RingElement') -> 'RingElement':
        return self.ring(self.val + other.val)


    def __elemsub__(self, other: 'RingElement') -> 'RingElement':
        return self + -other


    def __elemmul__(self, other: 'RingElement') -> 'RingElement':
        return self.ring(self.val * other.val)


    def __elemmod__(self, other: 'RingElement') -> 'RingElement':
        return self.ring(self.val % other.val)


    def __elemfloordiv__(self, other: 'QuotientElement') -> 'QuotientElement':
        return self.ring(self.val // other.val)


    def __elemdivmod__(self, other: 'RingElement') -> ('RingElement', 'RingElement'):
        return self // other, self % other


    def __elemtruediv__(self, other: 'RingElement') -> 'RingElement':
        return self * ~other


    def __check_precendence_override(self, other, other_func):
        try:
            return getattr(other, other_func).has_precedence_override
        except AttributeError:
            return False


    def __add__(self, other: 'RingElement') -> 'RingElement':
        if hasattr(other, 'ring'):
            if self.ring == other.ring:
                return self.__elemadd__(other)

            elif other.ring.is_superstructure_of(self.ring):
                return other.ring(self) + other


        return self.__elemadd__(self.ring.coerce(other))


    def __radd__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) + self


    def __sub__(self, other: 'RingElement') -> 'RingElement':
        if hasattr(other, 'ring') and other.ring.is_superstructure_of(self.ring):
            return other.ring(self) - other
        else:
            return self.__elemsub__(self.ring.coerce(other))


    def __rsub__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) - self


    def __mul__(self, other: 'RingElement') -> 'RingElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul


        if hasattr(other, 'ring'):
            if self.ring == other.ring:
                return self.__elemmul__(other)

            elif other.ring.is_superstructure_of(self.ring):
                return other.ring(self) * other
        
        return self.__elemmul__(self.ring.coerce(other))


    __pow__ = square_and_mul

    def __rmul__(self, other: int) -> 'RingElement':
        if type(other) is int:
            return self * other

        return self.ring.coerce(other) * self


    def __mod__(self, other: 'RingElement') -> 'RingElement':
        if hasattr(other, 'ring') and other.ring.is_superstructure_of(self.ring):
            return other.ring(self) % other
        elif self.__check_precendence_override(other, '__relemmod__'):
            return other.__relemmod__(self)
        else:
            return self.__elemmod__(self.ring.coerce(other))


    def __rmod__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) % self


    def __floordiv__(self, other: 'RingElement') -> 'RingElement':
        if hasattr(other, 'ring') and other.ring.is_superstructure_of(self.ring):
            return other.ring(self) // other
        else:
            return self.__elemfloordiv__(self.ring.coerce(other))


    def __divmod__(self, other: 'RingElement') -> ('RingElement', 'RingElement'):
        if hasattr(other, 'ring') and other.ring.is_superstructure_of(self.ring):
            return divmod(other.ring(self), other)
        elif self.__check_precendence_override(other, '__relemdivmod__'):
            return other.__relemdivmod__(self)
        else:
            return self.__elemdivmod__(self.ring.coerce(other))


    def __rdivmod__(self, other: 'RingElement') -> 'RingElement':
        return divmod(self.ring.coerce(other), self)


    def __invert__(self) -> 'RingElement':
        if self in [self.ring.one, -self.ring.one]:
            return self

        raise NotInvertibleException(f'{self} is not invertible', parameters={'a': self})


    def __truediv__(self, other: 'RingElement') -> 'RingElement':
        if not other:
            raise ZeroDivisionError

        # Is this just integer division?
        gmul = self.ground_div(other)
        if gmul is not None:
            return gmul

        # Try special cases
        if self.ring and other in self.ring:
            other = self.ring.coerce(other)

            if other == self.ring.one:
                return self

            elif other == self:
                return self.ring.one


        # Either we have element division or we have to promote
        try:
            return self.__elemtruediv__(other)

        except NotInvertibleException:
            if RUNTIME.auto_promote:
                elem = _frac.FractionField(self.ring)((self, other))

                if elem.denominator == self.ring.one:
                    elem = elem.numerator

                return elem
            else:
                raise


    def __rtruediv__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) / self


    def __rfloordiv__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) // self


    def __bool__(self) -> bool:
        return self != self.ring.zero


    def __eq__(self, other: 'RingElement') -> bool:
        other = self.ring.coerce(other)
        return self.val == other.val and self.ring == other.ring


    def __lt__(self, other: 'RingElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.val < other.val


    def __le__(self, other: 'RingElement') -> bool:
        return self < other or self == other


    def __gt__(self, other: 'RingElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.val > other.val


    def __ge__(self, other: 'RingElement') -> bool:
        return self > other or self == other


    def __int__(self) -> int:
        return int(self.val)


    def __abs__(self) -> 'RingElement':
        return self if self >= self.ring.zero else -self


    def ground_mul(self, other: 'RingElement') -> 'RingElement':
        """
        Tries "special" multiplications first.

        Parameter:
            other (RingElement): Other operand.
        
        Returns:
            RingElement/None: Returns the special __mul__ if possible.
        """
        type_o = type(other)

        if type_o is int:
            return fast_mul(self, other)


    def ground_div(self, other: 'RingElement') -> 'RingElement':
        """
        Tries "special" divisions first.

        Parameter:
            other (RingElement): Other operand.
        
        Returns:
            RingElement/None: Returns the special __div__ if possible.
        """

        type_o = type(other)

        if type_o is int and self.order() > 1:
            oo = _symb.oo

            if self.order() != oo:
                other = mod_inv(other, self.order())
                return fast_mul(self, other)


    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        return False


    def cache_op(self, start: 'RingElement', operation: FunctionType, size: int) -> 'BitVectorCache':
        """
        Caches a repeated `operation` in a `BitVectorCache`.

        Parameters:
            start (RingElement): Starting value.
            operation    (func): Operation to cache.
            size          (int): Size of cache.

        Returns:
            BitVectorCache: Cached vector.
        """
        from samson.math.bit_vector_cache import BitVectorCache
        return BitVectorCache(self, start, operation, size)


    def cache_mul(self, size: int) -> 'BitVectorCache':
        """
        Caches scalar multiplication (i.e. repeated addition) in a `BitVectorCache`.

        Parameters:
            size (int): Size of cache.

        Returns:
            BitVectorCache: Cached vector.
        """
        return self.cache_op(self.ring.zero, self.__class__.__add__, size)


    def cache_pow(self, size: int) -> 'BitVectorCache':
        """
        Caches exponentiation (i.e. repeated multiplication) in a `BitVectorCache`.

        Parameters:
            size (int): Size of cache.

        Returns:
            BitVectorCache: Cached vector.
        """
        return self.cache_op(self.ring.one, self.__class__.__mul__, size)


    def get_ground(self) -> 'RingElement':
        """
        Gets the "ground" value (i.e. IntegerElement or Polynomial). Useful for traversing complex
        algebras.

        Returns:
            RingElement: Ground element.

        Examples:
            >>> from samson.math.algebra.all import FF
            >>> F = FF(2, 8)
            >>> R = F/F[11]
            >>> R[5].get_ground()
            <Polynomial: x^2 + 1, coeff_ring=ZZ/(ZZ(2))>

        """
        from samson.math.algebra.rings.integer_ring import IntegerElement
        from samson.math.algebra.rings.padic_integers import PAdicIntegerElement

        if type(self) in [IntegerElement, _poly.Polynomial, _frac.FractionFieldElement, PAdicIntegerElement]:
            return self

        else:
            return self.val.get_ground()


    def order(self) -> int:
        """
        The minimum number of times the element can be added to itself before reaching the additive identity.

        Returns:
            int: Order.
        """
        if not self.order_cache:
            oo = _symb.oo

            if self.ring.order() == oo:
                return oo


            ro_facs = self.ring.order_factors()
            self.order_cache = self.find_maximum_subgroup(n_facs=ro_facs)

        return self.order_cache



    def find_maximum_subgroup(self, n: int=None, n_facs: 'Factors'=None) -> int:
        """
        Finds the maximum order of `self` in the subgroup of the size `n`.

        Parameters:
            n          (int): Size of the subgroup.
            n_facs (Factors): Factors of the size of the subgroup.

        Returns:
            int: Maximum order.
        """
        if not n and not n_facs:
            raise ValueError("Either 'n' or 'n_facs' must be provided")

        if n_facs:
            n = n_facs.recombine()
        else:
            n_facs = factor(n)


        so_facs = Factors()
        elem    = self.cache_mul(n.bit_length())

        for p in n_facs:
            e = n_facs[p]

            if e < 4:
                for i in range(1,e+2):
                    o = n // p**i
                    if elem*o != self.ring.zero:
                        break
            else:
                i = binary_search(lambda i: not elem*(n // p**i), e+1)

            so_facs[p] = e-(i-1)

        return so_facs.recombine()



    def is_irreducible(self) -> bool:
        """
        Determines if the element is irreducible by trial by division.

        Returns:
            bool: Whether or not the element is irreducible.
        """
        from samson.math.general import kth_root

        sord = self.ordinality()
        stop = kth_root(sord, 2)+1
        stop = min(stop, sord)

        for i in range(2, stop):
            if not self % self.ring[i]:
                return False

        return True



    def factor(self, attempts: int=1000) -> 'Factors':
        """
        Factors the element.

        Parameters:
            attempts (int): Number of ECM attempts before failure.

        Returns:
            Factors: Dictionary-like Factors object.
        """
        from samson.math.factorization.general import ecm
        from samson.math.factorization.factors import Factors
        from samson.analysis.general import count_items

        factors = []
        n       = self

        try:
            while not n.is_irreducible():
                q = ecm(n, attempts)
                n /= q
                q_facs = [[k for _ in range(v)] for k,v in q.factor().items()]
                factors.extend([item for sublist in q_facs for item in sublist])

        except KeyboardInterrupt:
            pass

        if n != self.ring.one:
            factors.append(n)

        return Factors(count_items(factors))


    def kth_root(self, k: int, return_all: bool=False, **root_kwargs) -> 'RingElement':
        """
        Computes the `k`-th root of `self`.

        Parameters:
            k              (int): Root to take.
            return_all    (bool): Whether or not to return all roots or just one.
            root_kwargs (kwargs): Kwargs to use with polynomial roots function.

        Returns:
            RingElement: Root(s).
        """
        Symbol = _symb.Symbol

        x = Symbol('x')
        _ = self.ring[x]

        if not return_all:
            root_kwargs['user_stop_func'] = lambda S: any(f.degree() == 1 for f in S)

        roots = (x**k - self).roots(**root_kwargs)

        if not roots:
            raise NoSolutionException()

        if not return_all:
            roots = roots[0]

        return roots



    def sqrt(self) -> 'RingElement':
        return self.kth_root(2)


    def is_square(self) -> bool:
        try:
            self.sqrt()
            return True
        except NoSolutionException:
            return False


    def gcd(self, other: 'RingElement') -> 'RingElement':
        a, b = self, other
        while b:
            a, b = b, a % b
        return a


    def _plog(self, base: 'RingElement', order: int) -> int:
        """
        Internal function for 'prime logarithm'. Called by Pohlig-Hellman
        to allow rings to define their own subalgorithms.
        """
        # BSGS is deterministic and generally faster, but it takes sqrt space.
        # This should cap memory usage at one million objects before moving to rho
        if order.bit_length() <= 40:
            return bsgs(base, self, end=order)
        else:
            return pollards_rho_log(base, self, order=order)



    def log(self, base: 'RingElement') -> int:
        """
        Computes the logarithm of `self` to `base`.

        Parameters:
            base (RingElement): Base.

        Returns:
            int: `x` such that `base`^`x` == `self`.
        """
        oo = _symb.oo

        mul = self.ring.mul_group()
        h   = mul(self)
        g   = mul(base)

        if self.ring.order() == oo:
            k = binary_search_unbounded(lambda guess: g*guess < h)

            if g*k == h:
                return k
            else:
                raise NotInvertibleException("Logarithm not found", parameters={'g': g, 'k': k, 'h': h})
        else:
            return pohlig_hellman(g, h)



    def merge(self, other: 'RingElement') -> 'RingElement':
        """
        Constructs an element such that its order is the LCM of the orders of `self` and `other`.

        Parameters:
            other (RingElement): Second element.

        Returns:
            RingElement: Element with order lcm(`self`.order(), `other`.order()).
        """
        n1 = self.order()
        n2 = other.order()

        if not n1 % n2:
            return self

        elif not n2 % n1:
            return other

        l, k1, k2 = xlcm(n1, n2)
        g = (self*(n1 // k1)) + (other*(n2 // k2))
        g.order_cache = l

        assert not g*l
        return g


    def linear_relation(self, other: 'RingElement') -> (int, int):
        """
        Finds a relation `n` and `m` such that `self`*`n` == `other`*`m`.

        Parameters:
            other (RingElement): Other element.

        Returns:
            (int, int): Formatted as (`n`, `m`).
        """
        n1 = self.order()
        n2 = other.order()

        g = gcd(n1, n2)

        if g == 1:
            return 0, n2

        n1 //= g
        n2 //= g

        P = self*n1
        Q = other*n2

        for h in factor(g).divisors():
            try:
                Q2 = Q*h
                return n1 * (Q2/P), n2*h
            except SearchspaceExhaustedException:
                pass

        raise NoSolutionException("No solution for linear relation (how did this happen?)")
