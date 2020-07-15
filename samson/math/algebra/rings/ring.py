from samson.math.general import fast_mul, square_and_mul, factor, is_prime
from types import FunctionType
from abc import ABC, abstractmethod
from functools import wraps, reduce
from itertools import combinations
from samson.utilities.runtime import RUNTIME
from samson.auxiliary.lazy_loader import LazyLoader
from samson.utilities.exceptions import CoercionException

poly = LazyLoader('poly', globals(), 'samson.math.polynomial')



def try_poly_first(element: object, other: object, func: FunctionType) -> object:
    """
    Tests if `other` is a Polynomial, and gives precedence to its operator.

    Parameters:
        other (RingElement): Possible Polynomial.
        func         (func): Function to execute.
    
    Returns:
        RingElement/None: The output of the Polynomial's function if possible.
    """
    if issubclass(type(other), poly.Polynomial) and other.coeff_ring == element.ring:
        return func(other, element)


def left_expression_intercept(func: FunctionType) -> object:
    """
    Intercepts "left" operators to give Polynomials precedence so elements from the coefficient ring can be coerced.
    """

    @wraps(func)
    def poly_build(*args, **kwargs):
        if RUNTIME.enable_poly_intercept:
            try:
                name = func.__name__
                name = '__r' + name[2:]
                poly_res = try_poly_first(*args, **kwargs, func=getattr(poly.Polynomial, name))

                if poly_res is not None:
                    return poly_res

            except Exception:
                pass

        return func(*args, **kwargs)

    return poly_build


class Ring(ABC):

    @abstractmethod
    def shorthand(self) -> str:
        pass


    def tinyhand(self) -> str:
        return ""


    def __str__(self):
        return self.shorthand()


    @property
    def structure_depth(self):
        if hasattr(self, 'ring'):
            return self.ring.structure_depth+1
        else:
            return 1


    def random(self, size: object) -> object:
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


    def coerce(self, other: object) -> 'RingElement':
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            RingElement: Coerced element.
        """
        return other


    def mul_group(self) -> 'MultiplicativeGroup':
        """
        Returns the `MultiplicativeGroup` of `self`.
        """
        from samson.math.algebra.rings.multiplicative_group import MultiplicativeGroup
        return MultiplicativeGroup(self)



    def __call__(self, args) -> 'RingElement':
        return self.coerce(args)


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


    @property
    def order(self) -> int:
        raise NotImplementedError()


    def find_gen(self) -> 'RingElement':
        """
        Finds a generator of the `Ring`.

        Returns:
            RingElement: A generator element.
        """
        from samson.utilities.exceptions import SearchspaceExhaustedException
        from samson.math.symbols import oo

        if self.order == oo:
            return self.one

        for i in range(1, self.order):
            possible_gen = self[i]
            if possible_gen * self.order == self.zero and possible_gen.order == self.order:
                return possible_gen

        raise SearchspaceExhaustedException("Unable to find generator")



    def __truediv__(self, element: 'RingElement') -> 'QuotientRing':
        from samson.math.algebra.rings.quotient_ring import QuotientRing
        if element.ring != self:
            raise RuntimeError("'element' must be an element of the ring")

        return QuotientRing(element, self)


    def __getitem__(self, x: int) -> 'RingElement':
        if type(x).__name__ == 'Symbol':
            from samson.math.algebra.rings.polynomial_ring import PolynomialRing
            return PolynomialRing(self, x)
        else:
            return self.element_at(x)


    def is_field(self) -> bool:
        from samson.math.symbols import oo
        return self.order != oo and is_prime(self.order)



class RingElement(ABC):
    def __init__(self, ring: Ring):
        self.ring = ring


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}({str(self.val)})'


    def tinyhand(self) -> str:
        return f'{self.val.tinyhand()}'


    def __str__(self):
        return RUNTIME.default_short_printer(self)

    def __hash__(self) -> int:
        return hash((self.ring, self.val))

    @abstractmethod
    def __add__(self, other: 'RingElement') -> 'RingElement':
        pass

    def __radd__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) + self

    @abstractmethod
    def __sub__(self, other: 'RingElement') -> 'RingElement':
        pass

    def __rsub__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) - self

    __mul__ = fast_mul
    __pow__ = square_and_mul

    def __rmul__(self, other: int) -> 'RingElement':
        if type(other) is int:
            return self * other

        return self.ring.coerce(other) * self


    def __rmod__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) % self

    def __rdivmod__(self, other: 'RingElement') -> 'RingElement':
        return divmod(self.ring.coerce(other), self)


    def __rtruediv__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) / self

    def __rfloordiv__(self, other: 'RingElement') -> 'RingElement':
        return self.ring.coerce(other) / self

    def __bool__(self) -> bool:
        return self != self.ring.zero

    def __eq__(self, other: 'RingElement') -> bool:
        other = self.ring.coerce(other)
        return self.val == other.val and self.ring == other.ring

    def __lt__(self, other: 'RingElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

        return self.val < other.val

    def __le__(self, other: 'RingElement') -> bool:
        return self < other or self == other

    def __gt__(self, other: 'RingElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise Exception("Cannot compare elements with different underlying rings.")

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

        # This is like a bajillion times faster than importing Poly
        elif type_o.__name__ in ['Polynomial', 'Symbol']:
            return try_poly_first(self, other, poly.Polynomial.__rmul__)


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
            <Polynomial: x**2 + 1, coeff_ring=ZZ/ZZ(2)>

        """
        from samson.math.algebra.rings.integer_ring import IntegerElement
        from samson.math.algebra.fields.fraction_field import FractionFieldElement

        if type(self) in [IntegerElement, poly.Polynomial, FractionFieldElement]:
            return self

        else:
            return self.val.get_ground()


    @property
    def order(self) -> int:
        """
        The minimum number of times the element can be added to itself before reaching the additive identity.

        Returns:
            int: Order.
        """
        from samson.math.symbols import oo

        if self.ring.order == oo:
            return oo

        expanded_factors = [1] + [item for fac, num in factor(self.ring.order).items() for item in [fac]*num]
        all_orders = []

        for product_size in range(1, len(expanded_factors)+1):
            for combination in set(combinations(expanded_factors, product_size)):
                product = reduce(int.__mul__, combination, 1)
                if self*product == self.ring.zero:
                    all_orders.append(product)

        return min(all_orders)



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
        from samson.math.general import ecm
        from samson.math.factors import Factors
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



    def sqrt(self) -> 'RingElement':
        from samson.math.general import kth_root
        return self.ring(kth_root(int(self.val), 2))


    def gcd(self, other: 'RingElement') -> 'RingElement':
        a, b = self, other
        while b:
            a, b = b, a % b
        return a
