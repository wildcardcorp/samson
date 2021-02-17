from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.utilities.exceptions import CoercionException, NotInvertibleException
from samson.math.general import newton_method_sizes
from samson.math.symbols import oo, Symbol
from samson.math.algebra.rings.polynomial_ring import PolynomialRing, Polynomial
from samson.utilities.runtime import RUNTIME


class PowerSeriesElement(RingElement):
    """
    Element of an `PowerSeriesRing`.
    """

    def __init__(self, val: Polynomial, ring: Ring):
        """
        Parameters:
            val (Polynomial): Value of the element.
            ring      (Ring): Parent ring.
        """
        self.val  = val[:ring.prec]
        self.ring = ring


    def __getattribute__(self, name):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = object.__getattribute__(self.val, name)

        return attr


    def __call__(self, val):
        return self.val(val)


    def derivative(self) -> 'PowerSeriesElement':
        return self.ring(self.val.derivative())


    def integral(self) -> 'PowerSeriesElement':
        return self.ring(self.val.integral())


    def degree(self) -> 'PowerSeriesElement':
        return self.val.degree()


    def tinyhand(self) -> str:
        return str(self.val)


    def valuation(self) -> int:
        coeffs = list(self.val.coeffs.values.items())
        if coeffs:
            return coeffs[0][0]
        else:
            return 0


    def order(self) -> int:
        """
        The minimum number of times the element can be added to itself before reaching the additive identity.

        Returns:
            int: Order.
        """
        return oo


    def __iter__(self):
        return self.val.__iter__()


    def __getitem__(self, idx: int) -> object:
        result = self.val[idx]

        if type(result) is Polynomial:
            return self.ring(result)
        else:
            return result


    def __setitem__(self, idx: int, value: 'RingElement'):
        self.val.coeffs[idx] = value


    def __lshift__(self, num: int):
        return PowerSeriesElement(self.val << num, self.ring)


    def __rshift__(self, num: int):
        return PowerSeriesElement(self.val >> num, self.ring)


    @left_expression_intercept
    def __add__(self, other: 'PowerSeriesElement') -> 'PowerSeriesElement':
        other = self.ring.coerce(other)
        return PowerSeriesElement(self.val + other.val, self.ring)


    @left_expression_intercept
    def __sub__(self, other: 'PowerSeriesElement') -> 'PowerSeriesElement':
        other = self.ring.coerce(other)
        return PowerSeriesElement(self.val - other.val, self.ring)
    

    def __invert__(self) -> 'PowerSeriesElement':
        p       = self.val
        const   = p[0]

        if const:
            P       = p.ring
            current = P(~const)

            def mul_trunc(p, q, prec):
                return ((p[:prec])*(q[:prec]))[:prec]

            for next_prec in newton_method_sizes(self.ring.prec)[1:]:
                z = mul_trunc(current, p, next_prec)
                z = mul_trunc(current, z, next_prec)
                current += current - z

            return PowerSeriesElement(current, self.ring)

        # Promote to Laurent series
        elif RUNTIME.auto_promote:
            return ~self.ring.fraction_field()(self)

        else:
            raise NotInvertibleException('Power series element not invertible when constant is zero', parameters={'p': p})


    @left_expression_intercept
    def __truediv__(self, other: 'PowerSeriesElement') -> 'PowerSeriesElement':
        other = self.ring.coerce(other)
        return self * ~other


    def __mul__(self, other: 'PowerSeriesElement') -> 'PowerSeriesElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul

        other = self.ring.coerce(other)
        return PowerSeriesElement(self.val * other.val, self.ring)


    @left_expression_intercept
    def __divmod__(self, other: 'PowerSeriesElement') -> ('PowerSeriesElement', 'PowerSeriesElement'):
        other = self.ring.coerce(other)
        q, r = divmod(self.val, other.val)
        return PowerSeriesElement(q, self.ring), PowerSeriesElement(r, self.ring)


    @left_expression_intercept
    def __mod__(self, other: 'PowerSeriesElement') -> 'PowerSeriesElement':
        return divmod(self, other)[1]


    @left_expression_intercept
    def __floordiv__(self, other: 'PowerSeriesElement') -> 'PowerSeriesElement':
        return divmod(self, other)[0]


    def __neg__(self) -> 'PowerSeriesElement':
        return PowerSeriesElement(-self.val, self.ring)


    def __eq__(self, other: 'PowerSeriesElement') -> bool:
        if type(other) is PowerSeriesElement:
            other = other.val

        return self.val == other


    def __hash__(self):
        return super().__hash__()


class PowerSeriesRing(Ring):
    def __init__(self, ring: Ring, symbol: Symbol=None, prec: int=20):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self._polyring = PolynomialRing(ring, symbol)
        symbol.top_ring = self
        self.symbol = symbol
        self.ring = ring
        self.prec = prec
        self.zero = self(0)
        self.one  = self(1)


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def __hash__(self) -> int:
        return hash(self._polyring, self.__class__)



    def __reprdir__(self):
        return ['ring', 'prec']


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}[[{self.symbol}]]'


    def fraction_field(self) -> 'Ring':
        """
        Returns:
            FractionField: A fraction field of self.
        """
        from samson.math.algebra.fields.laurent_series import LaurentSeriesRing
        return LaurentSeriesRing(self)


    def coerce(self, other: int) -> PowerSeriesElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (int): Object to coerce.
        
        Returns:
            PowerSeriesElement: Coerced element.
        """
        if type(other) is PowerSeriesElement and other.ring == self:
            return PowerSeriesElement(other.val, self)

        else:
            return PowerSeriesElement(self._polyring(other), self)

        raise CoercionException(self, other)



    def __eq__(self, other: 'PowerSeriesRing') -> bool:
        return type(self) == type(other) and other._polyring == self._polyring
