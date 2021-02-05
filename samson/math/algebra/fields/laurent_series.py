from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.utilities.exceptions import CoercionException, NotInvertibleException
from samson.math.symbols import oo, Symbol
from samson.math.algebra.rings.power_series_ring import PowerSeriesElement, PowerSeriesRing
import operator


class LaurentSeriesElement(RingElement):
    """
    Element of an `LaurentSeriesRing`.
    """

    def __init__(self, val: PowerSeriesElement, shift: int, ring: Ring):
        """
        Parameters:
            val (PowerSeriesElement): Value of the element.
            ring              (Ring): Parent ring.
        """
        self.val   = val
        self.shift = shift
        self.ring  = ring


    def __getattribute__(self, name):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = object.__getattribute__(self.val, name)

        return attr


    @property
    def _poly(self):
        return self.tinyhand()


    def __reprdir__(self):
        return ['_poly', 'ring']


    def __call__(self, val):
        return self.val(val)


    def tinyhand(self) -> str:
        return self.val.val.shorthand(tinyhand=True, idx_mod=-self.shift)



    def derivative(self) -> 'LaurentSeriesElement':
        val = self.ring.ring._polyring({idx:c*(idx-self.shift) for idx, c in self.val.val.coeffs.values.items()})
        return LaurentSeriesElement(self.ring.ring(val), self.shift+1, self.ring)


    def integral(self) -> 'LaurentSeriesElement':
        val = self.ring.ring._polyring({idx:c/(idx-self.shift+1) for idx, c in self.val.val.coeffs.values.items()})
        return LaurentSeriesElement(self.ring.ring(val), self.shift-1, self.ring)


    def degree(self) -> 'LaurentSeriesElement':
        return self.val.degree()-self.shift


    def truncate(self, precision: int) -> 'LaurentSeriesElement':
        return LaurentSeriesElement(self.val[:precision+self.shift], self.shift, self.ring)


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
        idx_modded = idx+self.shift

        if idx_modded >= 0:
            result = self.val[idx_modded]

            if type(result) is PowerSeriesElement:
                return LaurentSeriesElement(result, self.shift, self.ring)
            else:
                return result
        else:
            return self.val.val.coeff_ring.zero



    def __setitem__(self, idx: int, value: 'RingElement'):
        idx_modded = idx+self.shift

        if idx_modded < 0:
            self.val.val = self.val.val << -idx_modded
            self.shift  += -idx_modded
            idx_modded = 0

        self.val.val.coeffs[idx_modded] = value


    def __lshift__(self, num: int):
        return LaurentSeriesElement(self.val, self.shift-num, self.ring)


    def __rshift__(self, num: int):
        return LaurentSeriesElement(self.val, self.shift+num, self.ring)
    

    def __do_op(self, other, op):
        other = self.ring.coerce(other)

        s_val, o_val     = self.val, other.val
        s_shift, o_shift = self.shift, other.shift

        # Prevent poly underflow
        u_shift = max(max(s_shift - s_val.valuation(), o_shift - o_val.valuation()), 0)
        s_val <<= u_shift
        o_val <<= u_shift

        # Align
        s_val <<= -s_shift
        o_val <<= -o_shift

        # For mul, we need to undo the underflow shift twice
        # since degrees add
        if op == operator.mul:
            u_shift *= 2

        val = self.ring(op(s_val, o_val)) >> u_shift
        return val



        # # Prevent poly underflow
        # u_shift = max(max(s_shift - s_val.val.degree(), o_shift - o_val.val.degree()), 0)
        # s_val <<= u_shift
        # o_val <<= u_shift

        # # Align
        # s_val <<= -s_shift
        # o_val <<= -o_shift

        # val   = (op(s_val, o_val)) >> u_shift*2
        # # shift = val.valuation() - u_shift

        # # val = val << -shift
        # # shift = val.valuation()
        # # val <<= -shift
        # shift = val.valuation()
        # val <<= -shift

        # return val, shift



    @left_expression_intercept
    def __add__(self, other: 'LaurentSeriesElement') -> 'LaurentSeriesElement':
        #return LaurentSeriesElement(*self.__do_op(other, operator.add), self.ring)
        return self.__do_op(other, operator.add)


    @left_expression_intercept
    def __sub__(self, other: 'LaurentSeriesElement') -> 'LaurentSeriesElement':
        #return LaurentSeriesElement(*self.__do_op(other, operator.sub), self.ring)
        return self.__do_op(other, operator.sub)
    

    def __invert__(self) -> 'LaurentSeriesElement':
        return LaurentSeriesElement(~self.val, -self.shift, self.ring)



    @left_expression_intercept
    def __truediv__(self, other: 'LaurentSeriesElement') -> 'LaurentSeriesElement':
        other = self.ring.coerce(other)
        return self * ~other


    def __mul__(self, other: 'LaurentSeriesElement') -> 'LaurentSeriesElement':
        gmul = self.ground_mul(other)
        if gmul is not None:
            return gmul


        # other = self.ring.coerce(other)
        # shift = -self.shift + -other.shift
        # val   = (self.val.val << -self.shift)*(other.val.val << -other.shift)

        # if shift > 0:
        #     shifted = val >> shift
        # else:
        #     shifted = val << -shift

        # return LaurentSeriesElement(self.ring.ring(shifted), -shift, self.ring)
        #val, shift = self.__do_op(other, operator.mul)
        #shift      = self.shift + other.shift
        #return LaurentSeriesElement(val, shift, self.ring)
        return self.__do_op(other, operator.mul)


    def __neg__(self) -> 'LaurentSeriesElement':
        return LaurentSeriesElement(-self.val, self.shift, self.ring)


    def __eq__(self, other: 'LaurentSeriesElement') -> bool:
        if other is LaurentSeriesElement:
            other = other.val

        return self.val == other


    def __hash__(self):
        return super().__hash__()



class LaurentSeriesRing(Ring):
    def __init__(self, ring: Ring):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring = ring
        self.zero = self(0)
        self.one  = self(1)


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def is_field(self) -> bool:
        return self.ring.is_field()


    def __hash__(self) -> int:
        return hash(self.ring, self.__class__)


    def __reprdir__(self):
        return ['ring', 'prec']


    def shorthand(self) -> str:
        return f'{self.ring.ring.shorthand()}(({self.ring.symbol}))'


    def coerce(self, other: int) -> LaurentSeriesElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (int): Object to coerce.

        Returns:
            LaurentSeriesElement: Coerced element.
        """
        if type(other) is LaurentSeriesElement and other.ring == self:
            return LaurentSeriesElement(other.val, other.shift, self)

        else:
            other = self.ring(other)
            val   = other.valuation()
            return LaurentSeriesElement(other << -val, -val, self)

        raise CoercionException(self, other)



    def __eq__(self, other: 'LaurentSeriesRing') -> bool:
        return type(self) == type(other) and other.ring == self.ring
