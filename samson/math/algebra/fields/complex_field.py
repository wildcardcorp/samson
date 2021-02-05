from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.fields.real_field import RealField, RealElement
from samson.utilities.exceptions import CoercionException

class ComplexElement(RealElement):
    """
    Element of a `ComplexField`.
    """

    def sqrt(self) -> 'ComplexElement':
        return self.field(self.field.ctx.sqrt(self.val))


    def kth_root(self, k:int) -> 'ComplexElement':
        return self**(self.field(1)/self.field(k))


    def real(self):
        return RealField(ctx=self.field.ctx)(self.val.real)


    def imag(self):
        return RealField(ctx=self.field.ctx)(self.val.imag)



class ComplexField(RealField):

    def shorthand(self) -> str:
        return 'CC'


    def coerce(self, other: object) -> ComplexElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.
        
        Returns:
            ComplexElement: Coerced element.
        """
        if hasattr(other, 'ring') and other.ring == self:
            return other

        else:
            imag = 0
            if type(other) in [tuple, list]:
                other, imag = other

            try:
                return ComplexElement(self.ctx.mpc(other, imag), self)
            except ValueError as e:
                raise CoercionException((other, imag)) from e


    def random(self, size: object=None) -> object:
        """
        Generate a random element.

        Parameters:
            size (int/FieldElement): The maximum ordinality/element (non-inclusive).
    
        Returns:
            FieldElement: Random element of the algebra.
        """
        from samson.math.general import random_int

        if not size:
            size = 2**self.prec

        n, d = self(size).val.as_integer_ratio()
        a, b = [self(random_int(n))/self(max(1, random_int(d))) for _ in range(2)]
        return self((a,b))


CC = ComplexField()
