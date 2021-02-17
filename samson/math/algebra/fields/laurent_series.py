from samson.math.algebra.rings.ring import Ring, RingElement, left_expression_intercept
from samson.utilities.exceptions import CoercionException, NotInvertibleException
from samson.math.symbols import oo, Symbol
from samson.math.algebra.rings.power_series_ring import PowerSeriesElement, PowerSeriesRing
from samson.math.algebra.rings.polynomial_ring import Polynomial
from samson.math.algebra.fields.negative_degree_field import NegativeDegreeElement, NegativeDegreeField
import operator


class LaurentSeriesElement(NegativeDegreeElement):
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
        return self.val(val) / val**self.shift


    def tinyhand(self) -> str:
        return self.val.val.shorthand(tinyhand=True, idx_mod=-self.shift)


    def degree(self) -> 'int':
        return self.val.degree()-self.shift


    def derivative(self) -> 'LaurentSeriesElement':
        val = self.ring.ring._polyring({idx:c*(idx-self.shift) for idx, c in self.val.val.coeffs.values.items()})
        return LaurentSeriesElement(self.ring.ring(val), self.shift+1, self.ring)


    def integral(self) -> 'LaurentSeriesElement':
        val = self.ring.ring._polyring({idx:c/(idx-self.shift+1) for idx, c in self.val.val.coeffs.values.items()})
        return LaurentSeriesElement(self.ring.ring(val), self.shift-1, self.ring)



    def __getitem__(self, idx: int) -> object:
        result = super().__getitem__(idx)
        if type(result) is PowerSeriesElement:
            return LaurentSeriesElement(result, self.shift, self.ring)
        else:
            return result



class LaurentSeriesRing(NegativeDegreeField):
    ELEMENT = LaurentSeriesElement

    def __init__(self, ring: Ring):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        self.ring = ring
        self.zero = self(0)
        self.one  = self(1)


    def __reprdir__(self):
        return ['ring']


    def shorthand(self) -> str:
        return f'{self.ring.ring.shorthand()}(({self.ring.symbol}))'


    def _precheck_val(self, other):
        if type(other) is PowerSeriesElement:
            val = other.valuation()
            return other << -val, val

        elif type(other) is Polynomial:
            val = list(other.coeffs.values.keys())[0]
            return other << -val, val

        else:
            return other, None
