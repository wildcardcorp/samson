from samson.math.polynomial import Polynomial
from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.fields.fraction_field import FractionFieldElement
from samson.math.symbols import  oo
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.symbols import Symbol, oo
from samson.math.factorization.general import factor
from samson.math.matrix import Matrix


class NumberFieldElement(FractionFieldElement):
    def __init__(self, numerator: 'FieldElement', denominator: 'FieldElement', field: Field):
        FieldElement.__init__(self, field)
        self.numerator   = numerator
        self.denominator = denominator

    def __reprdir__(self):
        return ['numerator', 'denominator', 'field']


    def is_integral(self) -> bool:
        return self.denominator == self.field.ring.one


    def __iter__(self):
        z = ZZ.fraction_field().zero
        d = self.field.degree()
        n = self.val.val.degree()+1

        for c in (list(self.val.val) + [z]*(d-n)):
            yield c


    def matrix(self) -> Matrix:
        cur = Matrix([list(self)])
        X   = self.field.generator_matrix()
        v   = [list(cur)[0]]

        for _ in range(self.field.degree()-1):
            cur *= X
            v   += [list(cur)[0]]

        return Matrix(v)
    

    def is_rational(self) -> bool:
        return not self.val.val.degree()


    def minimum_polynomial(self) -> Polynomial:
        if self.is_rational():
            x = Symbol('x')
            _ = ZZ.fraction_field()[x]
            return x - list(self)[0]
        
        else:
            return self.matrix().characteristic_polynomial()



class NumberField(Field):
    def __init__(self, ring: 'Order'):
        self.ring = ring
        self.one  = NumberFieldElement(self.ring.one, self.ring.one, self)
        self.zero = NumberFieldElement(self.ring.zero, self.ring.one, self)


    def __getattribute__(self, name):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = object.__getattribute__(self.ring, name)

        return attr


    def __reprdir__(self):
        return ['defining_polynomial']


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def shorthand(self) -> str:
        return f'QQ[{self.ring.symbol}]'


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def is_superstructure_of(self, R: 'Ring') -> bool:
        """
        Determines whether `self` is a superstructure of `R`.

        Parameters:
            R (Ring): Possible substructure.

        Returns:
            bool: Whether `self` is a superstructure of `R`.
        """
        return R == self.ring or self.ring.is_superstructure_of(R)


    def coerce(self, other: object) -> NumberFieldElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            NumberFieldElement: Coerced element.
        """
        if not type(other) is NumberFieldElement:
            other = NumberFieldElement(self.ring(other), self.ring.one, self)

        return other


    def element_at(self, x: int) -> NumberFieldElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           NumberFieldElement: The `x`-th element.
        """
        return NumberFieldElement(self.internal_field.element_at(x), self)


    def random(self, size: NumberFieldElement=None) -> NumberFieldElement:
        if size is not None:
            size = size.val
        return self(self.internal_field.random(size))


    def __eq__(self, other: 'NumberField') -> bool:
        return type(self) == type(other) and self.internal_field == other.internal_field


    def degree(self) -> int:
        return self.defining_polynomial.degree()
    

    def discriminant(self) -> int:
        D = ZZ(self.defining_polynomial.discriminant())
        d = factor(int(D)).square_free().recombine()

        if d % 4 != 1:
            d *= 4
        
        return d


    def generator_matrix(self) -> Matrix:
        x = self.symbol
        a = x
        d = self.degree()
        v = [list((x*1))]

        for _ in range(d-1):
            a *= x
            v += [list(a)]
        
        return Matrix(v)
