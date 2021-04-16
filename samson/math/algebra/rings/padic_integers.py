from samson.math.algebra.rings.ring import Ring, RingElement
from samson.utilities.exceptions import CoercionException
from samson.auxiliary.lazy_loader import LazyLoader
from samson.math.general import mod_inv
from samson.math.symbols import oo
from samson.auxiliary.theme import PADIC_COEFF, PADIC_DEGREE, color_format

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
        super().__init__(ring)


    def shorthand(self, idx_mod: int=0) -> str:
        parts = []
        p = str(self.ring.p)
        for i, e in enumerate(self.val):
            if e:
                i += idx_mod
                e  = color_format(PADIC_COEFF, e)
                if not i:
                    parts.append(str(e))
                elif i == 1:
                    parts.append(f"{e}*{p}")
                else:
                    parts.append(f"{e}*{p}^{color_format(PADIC_DEGREE, i)}")

        vals = ' + '.join(parts)
        if not vals:
            vals = '0'
        return vals + f' + O({self.ring.p}^{self.ring.prec})'


    def tinyhand(self) -> str:
        return self.shorthand()


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


    def valuation(self) -> int:
        for i, e in enumerate(self.val):
            if e:
                break

        return i


    def __getitem__(self, idx: int) -> object:
        return self.val[idx]


    def __elemadd__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        result = []
        carry  = 0

        for a,b in zip(self.val, other.val):
            c     = a+b+carry
            carry = c // self.ring.p
            c    %= self.ring.p

            result.append(c)

        return PAdicIntegerElement(result, self.ring)


    def __elemmul__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
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
        return self.valuation()


    def __invert__(self) -> 'FractionFieldElement':
        if not self:
            raise ZeroDivisionError

        return self.ring.one / self


    def __lshift__(self, num: int):
        if num < 0:
            return self >> -num
        else:
            return PAdicIntegerElement(([0]*num + [e for e in self.val])[:self.ring.prec], self.ring)


    def __rshift__(self, num: int):
        if num < 0:
            return self << -num
        else:
            return PAdicIntegerElement([e for e in self.val][num:] + [0]*num, self.ring)



    def __elemtruediv__(self, other: 'PAdicIntegerElement'):
        """
        References:
            https://math.stackexchange.com/questions/250097/how-do-you-take-the-multiplicative-inverse-of-a-p-adic-number
        """
        divisor  = other
        result   = []
        dividend = PAdicIntegerElement([e for e in self.val], self.ring)

        if not dividend:
            return dividend

        a = divisor.val[0]

        if not a:
            raise ZeroDivisionError

        i = 0
        a_inv = mod_inv(a, self.ring.p)
        while i < self.ring.prec:
            b = dividend.val[i]
            if a:
                c         = (b*a_inv) % self.ring.p
                dividend -= (divisor << i) * c
            else:
                c = 0

            result.append(c)
            i += 1

        return PAdicIntegerElement(result, self.ring)



    def __elemdivmod__(self, other: 'PAdicIntegerElement') -> ('PAdicIntegerElement', 'PAdicIntegerElement'):
        return self / other, self.ring.zero

    def __elemmod__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        return self.ring.zero


    def __elemfloordiv__(self, other: 'PAdicIntegerElement') -> 'PAdicIntegerElement':
        return self / other


    def __neg__(self) -> 'PAdicIntegerElement':
        p = self.ring.p
        carry, coeff_zero = divmod(p-self.val[0], p)
        places = [coeff_zero]
        for e in self.val[1:]:
            carry, v = divmod(p-1-e+carry, p)
            places.append(v)

        return PAdicIntegerElement(places, self.ring)


    def __eq__(self, other: 'PAdicIntegerElement') -> bool:
        other = self.ring(other)
        return self.val == other.val


    def __hash__(self):
        return hash((self.ring, tuple(self.val)))



class PAdicIntegerRing(Ring):

    def __init__(self, p: int, prec: int=20):
        super().__init__()
        self.p    = int(p)
        self.prec = int(prec)
        self.zero = self(0)
        self.one  = self(1)


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def __hash__(self) -> int:
        return hash((self.__class__, self.p, self.prec))


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


    def fraction_field(self) -> 'Ring':
        """
        Returns:
            FractionField: A fraction field of self.
        """
        from samson.math.algebra.rings.padic_numbers import PAdicNumberField
        return PAdicNumberField(self)


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
