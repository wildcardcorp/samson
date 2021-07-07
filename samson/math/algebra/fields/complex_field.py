from samson.math.algebra.fields.real_field import RealField, RealElement
from samson.utilities.exceptions import CoercionException

class ComplexElement(RealElement):
    """
    Element of a `ComplexField`.
    """

    def sqrt(self) -> 'ComplexElement':
        return self.field(self.field.ctx.sqrt(self.val))


    def kth_root(self, k: int, return_all: bool=False) -> 'ComplexElement':
        C    = self.field
        base = self**(C(1)/C(k))

        if return_all:
            roots = [base]
            roots.extend([base*C.e**(2*C.pi*1j*i / k) for i in range(1, k)])
            return roots

        else:
            return base


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
            type_o = type(other)
            if type_o in [tuple, list]:
                other, imag = other

            elif type_o == RealElement:
                other = other.val

            try:
                return ComplexElement(self.ctx.mpc(other, imag), self)
            except (ValueError, TypeError) as e:
                raise CoercionException((other, imag)) from e


    def random(self, size: object=None) -> ComplexElement:
        """
        Generate a random element.

        Parameters:
            size (int/ComplexElement): The maximum ordinality/element (non-inclusive).
    
        Returns:
            ComplexElement: Random element of the algebra.
        """
        return self(super().random(size) + super().random(size)*1j)


CC = ComplexField()