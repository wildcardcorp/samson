from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.utilities.exceptions import CoercionException
from samson.auxiliary.lazy_loader import LazyLoader
from samson.math.general import mod_inv
from samson.math.symbols import oo

_integer_ring = LazyLoader('_integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')

class PAdicIntegerElement(RingElement):
    """
    Element of an `PAdicIntegerRing`.
    """

    def __init__(self, val: int, ring: Ring):
        """
        Parameters:
            val   (int): Value of the element.
            ring (Ring): Parent ring.
        """
        self.val  = ([int(e) for e in val] + [0] * (ring.prec-len(val)))[:ring.prec]
        self.ring = ring


    def shorthand(self) -> str:
        parts = []
        p = str(self.ring.p)
        for i, e in enumerate(self.val):
            if e:
                if not i:
                    parts.append(str(e))
                elif i == 1:
                    parts.append(f"{e}*{p}")
                else:
                    parts.append(f"{e}*{p}^{i}")

        vals = ' + '.join(parts)
        if not vals:
            vals = '0'
        return vals + f' + O({self.ring.p}^{self.ring.prec})'


    def tinyhand(self) -> str:
        return self.shorthand()


    def valuation(self, p: int) -> int:
        from samson.math.symbols import oo

        if not self:
            return oo

        v = -1
        r = 0
        int_self = int(self)
        while not r:
            v += 1
            int_self, r = divmod(int_self, p)

        return v


    def order(self) -> int:
        """
        The minimum number of times the element can be added to itself before reaching the additive identity.

        Returns:
            int: Order.
        """
        return oo


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return int(self)
    

    def __int__(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return sum([e*self.ring.p**i for i, e in enumerate(self.val)])


    def degree(self) -> int:
        for i, e in enumerate(self.val):
            if e:
                break

        return len(self.val)-i


    @left_expression_intercept
    def __add__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        other  = self.ring.coerce(other)
        result = []
        carry  = 0

        for a,b in zip(self.val, other.val):
            c     = a+b+carry
            carry = c // self.ring.p
            c    %= self.ring.p

            result.append(c)

        return PAdicIntegerElement(result, self.ring)


    @left_expression_intercept
    def __sub__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        other = self.ring.coerce(other)
        return self + -other


    def __mul__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul


        other  = self.ring.coerce(other)
        result = [0]*self.ring.prec*2

        for i, a in enumerate(self.val):
            carry = 0

            for j, b in enumerate(other.val):
                result[i+j] += a*b+carry
                carry        = result[i+j] // self.ring.p
                result[i+j] %= self.ring.p


        if carry:
            result.append(carry)

        return PAdicIntegerElement(result, self.ring)


    def __abs__(self):
        return self.degree()


    def __invert__(self) -> 'FractionFieldElement':
        if not self:
            raise ZeroDivisionError

        return self.ring.one / self
    


    def __lshift__(self, num: int):
        return PAdicIntegerElement([e for e in self.val][num:] + [0]*num, self.ring)


    def __rshift__(self, num: int):
        return PAdicIntegerElement(([0]*num + [e for e in self.val])[:self.ring.prec], self.ring)



    def __truediv__(self, other: 'PAdicIntegerElement'):
        """
        References:
            https://math.stackexchange.com/questions/250097/how-do-you-take-the-multiplicative-inverse-of-a-p-adic-number
        """
        divisor  = self.ring.coerce(other)
        result   = []
        dividend = PAdicIntegerElement([e for e in self.val], self.ring)

        a = divisor.val[0]

        i = 0
        while i < self.ring.prec:
            b = dividend.val[i]
            if a:
                c         = (b*mod_inv(a, self.ring.p)) % self.ring.p
                dividend -= (divisor >> i) * c
            else:
                c = 0

            result.append(c)
            i += 1

        return PAdicIntegerElement(result, self.ring)



    @left_expression_intercept
    def __divmod__(self, other: 'PAdicIntegerElement') -> ('PAdicIntegerElement', 'PAdicIntegerElement'):
        return self/other, self.ring.zero

    @left_expression_intercept
    def __mod__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        return self.ring.zero


    @left_expression_intercept
    def __floordiv__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        return self/other


    def __neg__(self) -> 'PAdicIntegerElement':
        return PAdicIntegerElement([self.ring.p-self.val[0]] + [self.ring.p-1-e for e in self.val[1:]], self.ring)


    def __eq__(self, other: 'PAdicIntegerElement') -> bool:
        other = self.ring(other)
        return self.val == other.val


    def __hash__(self):
        return super().__hash__()


class PAdicIntegerRing(Ring):

    def __init__(self, p: int, prec: int=20):
        self.p    = int(p)
        self.prec = int(prec)
        self.zero = self(0)
        self.one  = self(1)


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def __hash__(self) -> int:
        return hash(self.__class__)


    def element_at(self, x: int) -> PAdicIntegerElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           PAdicIntegerElement: The `x`-th element.
        """
        return self(x)


    def __reprdir__(self):
        return ['p', 'prec']


    def shorthand(self) -> str:
        return f'Zp_{self.p}'


    def _decompose_integer(self, element: int) -> list:
        base_coeffs = []

        # Use != to handle negative numbers
        while element != 0 and element != -1:
            element, r = divmod(element, self.p)
            base_coeffs.append(r)

        return base_coeffs


    def coerce(self, other: int) -> PAdicIntegerElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (int): Object to coerce.
        
        Returns:
            PAdicIntegerElement: Coerced element.
        """
        if type(other) is PAdicIntegerElement:
            return other

        if other in _integer_ring.ZZ:
            other = int(_integer_ring.ZZ(other))

        if type(other) is int:
            return PAdicIntegerElement(self._decompose_integer(other), self)




        raise CoercionException(self, other)


    def __eq__(self, other: 'PAdicIntegerRing') -> bool:
        return type(self) == type(other) and self.p == other.p and self.prec == other.prec


    def random(self, size: object=None) -> object:
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
            return self(random_int(self.p**self.prec))


Zp = PAdicIntegerRing
