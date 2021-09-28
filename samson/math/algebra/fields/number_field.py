from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import hilbert_class_polynomial
from samson.math.symbols import Symbol, oo
from samson.math.factorization.general import factor

class NumberFieldElement(FieldElement):
    def __init__(self, val: 'FieldElement', field: Field):
        super().__init__(field)
        self.val = val
    
    def __reprdir__(self):
        return ['val', 'field']


    def __invert__(self) -> 'NumberFieldElement':
        return NumberFieldElement(~self.val, self.field)


    def __neg__(self) -> 'NumberFieldElement':
        return NumberFieldElement(-self.val, self.field)


class NumberField(Field):
    def __init__(self, defining_polynomial: 'Polynomial'):
        self.defining_polynomial = defining_polynomial
        self.symbol = defining_polynomial.symbol
        self.internal_field = ZZ.fraction_field()[self.symbol]/self.defining_polynomial
        self.symbol.top_ring = self

        self.one  = NumberFieldElement(self.internal_field.one, self)
        self.zero = NumberFieldElement(self.internal_field.zero, self)


    def __reprdir__(self):
        return ['defining_polynomial']


    def __hash__(self) -> int:
        return hash((self.internal_field, self.__class__))


    def shorthand(self) -> str:
        return f'QQ[{self.symbol}]'


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
        return self.internal_field.is_superstructure_of(R)


    def coerce(self, other: object) -> NumberFieldElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            NumberFieldElement: Coerced element.
        """
        if not type(other) is NumberFieldElement:
            other = NumberFieldElement(self.internal_field(other), self)

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


    def degree(self):
        return self.defining_polynomial.degree()
    

    def discriminant(self):
        D = ZZ(self.defining_polynomial.discriminant())
        d = factor(int(D)).square_free().recombine()

        if d % 4 != 1:
            d *= 4
        
        return d


    def hilbert_class_polynomial(self):
        disc = self.discriminant()

        if disc > 0:
            raise ValueError('Discriminant cannot be positive')

        return hilbert_class_polynomial(int(disc))



def QuadraticField(D: int, symbol_name: str=None) -> 'NumberField':
    if ZZ(D).is_square():
        raise ValueError(f'"D" ({D}) cannot be square')
    
    if not symbol_name:
        symbol_name = f'√{D}'
    
    x = Symbol(symbol_name)
    ZZ.fraction_field()[x]

    return NumberField(x**2 - D)