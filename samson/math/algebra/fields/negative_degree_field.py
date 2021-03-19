from samson.math.algebra.rings.ring import Ring, RingElement
from samson.utilities.exceptions import CoercionException
from samson.math.symbols import oo
import operator


class NegativeDegreeElement(RingElement):
    """
    Element of an `NegativeDegreeField`.
    """

    def __init__(self, val: RingElement, shift: int, ring: Ring):
        """
        Parameters:
            val (RingElement): Value of the element.
            ring       (Ring): Parent ring.
        """
        self.val   = val
        self.shift = shift
        super().__init__(ring)


    def valuation(self) -> 'int':
        return self.val.valuation()-self.shift


    def truncate(self, precision: int) -> 'NegativeDegreeElement':
        return self.ring.ELEMENT(self.val[:precision+self.shift], self.shift, self.ring)


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
            return self.val[idx_modded]
        else:
            return self.val.val.coeff_ring.zero



    def __setitem__(self, idx: int, value: 'RingElement'):
        idx_modded = idx+self.shift

        if idx_modded < 0:
            self.val.val = self.val.val << -idx_modded
            self.shift  += -idx_modded
            idx_modded = 0

        self.val.val[idx_modded] = value


    def __lshift__(self, num: int):
        return self.ring.ELEMENT(self.val, self.shift-num, self.ring)


    def __rshift__(self, num: int):
        return self.ring.ELEMENT(self.val, self.shift+num, self.ring)


    def __do_op(self, other, op):
        other = self.ring.coerce(other)

        s_val, o_val     = self.val, other.val
        s_shift, o_shift = self.shift, other.shift

        # If they have a shift of the same sign, we can remove it before
        # calculations for greater precision
        rel_shift = 0
        if (s_shift > 0) == (o_shift > 0):
            rel_shift = min(abs(s_shift), abs(o_shift))

            if s_shift < 0:
                rel_shift = -rel_shift


        s_shift -= rel_shift
        o_shift -= rel_shift


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
            u_shift   *= 2
            rel_shift *= 2

        val = self.ring(op(s_val, o_val)) >> u_shift + rel_shift
        return val


    def __elemadd__(self, other: 'NegativeDegreeElement') -> 'NegativeDegreeElement':
        return self.__do_op(other, operator.add)


    def __elemsub__(self, other: 'NegativeDegreeElement') -> 'NegativeDegreeElement':
        return self.__do_op(other, operator.sub)


    def __invert__(self) -> 'NegativeDegreeElement':
        return self.ring.ELEMENT(~self.val, -self.shift, self.ring)


    def __elemmul__(self, other: 'NegativeDegreeElement') -> 'NegativeDegreeElement':
        return self.__do_op(other, operator.mul)


    def __neg__(self) -> 'NegativeDegreeElement':
        return self.ring.ELEMENT(-self.val, self.shift, self.ring)


    def __eq__(self, other: 'NegativeDegreeElement') -> bool:
        if type(other) is self.ring.ELEMENT:
            other = other.val >> other.shift

        return self.val >> self.shift == other


    def __hash__(self):
        return hash((self.val, self.shift, self.ring))



class NegativeDegreeField(Ring):
    ELEMENT = None

    def __init__(self, ring: Ring):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring = ring


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def is_field(self) -> bool:
        return self.ring.is_field()


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def __reprdir__(self):
        return ['ring']


    def coerce(self, other: int) -> NegativeDegreeElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (int): Object to coerce.

        Returns:
            NegativeDegreeElement: Coerced element.
        """
        if type(other) is self.ELEMENT and other.ring == self:
            return self.ELEMENT(other.val, other.shift, self)

        else:
            other, val = self._precheck_val(other)
            other      = self.ring(other)
            if val is None:
                val = other.valuation()

            return self.ELEMENT(other, -val, self)

        raise CoercionException(self, other)



    def __eq__(self, other: 'NegativeDegreeField') -> bool:
        return type(self) == type(other) and other.ring == self.ring
