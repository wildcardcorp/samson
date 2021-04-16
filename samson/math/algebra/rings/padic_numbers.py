from samson.math.algebra.rings.ring import Ring
from samson.math.algebra.rings.padic_integers import PAdicIntegerRing
from samson.math.algebra.fields.negative_degree_field import NegativeDegreeElement, NegativeDegreeField
from samson.auxiliary.lazy_loader import LazyLoader

_integer_ring = LazyLoader('_integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')

class PAdicNumberElement(NegativeDegreeElement):
    """
    Element of an `PAdicNumberField`.
    """

    def shorthand(self) -> str:
        return self.val.shorthand(-self.shift)


    def tinyhand(self) -> str:
        return self.shorthand()


    def __int__(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return sum([e*self.ring.p**(i-self.shift) for i, e in enumerate(self.val)])



class PAdicNumberField(NegativeDegreeField):
    ELEMENT = PAdicNumberElement

    def __init__(self, ring: Ring):
        super().__init__(ring)
        self.zero = self(0)
        self.one  = self(1)


    def _precheck_val(self, other):
        other  = int(other)
        decomp = self.ring._decompose_integer(other)
        i = 0
        for i, e in enumerate(decomp):
            if e:
                break

        return other // self.ring.p**i, i


    def element_at(self, x: int) -> PAdicNumberElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.
        
        Returns:
           PAdicNumberElement: The `x`-th element.
        """
        return self(x)
    

    def is_field(self):
        return _integer_ring.ZZ(self.p).is_prime()


    @property
    def p(self):
        return self.ring.p


    @property
    def prec(self):
        return self.ring.prec


    def __reprdir__(self):
        return ['p', 'prec']


    def shorthand(self) -> str:
        return f'Qp_{self.ring.p}'


def Qp(p, prec):
    return PAdicIntegerRing(p=p, prec=prec).fraction_field()
