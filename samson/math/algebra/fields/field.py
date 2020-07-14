from abc import abstractmethod #ABC,
from samson.math.algebra.rings.ring import RingElement, Ring

class Field(Ring):
    """
    Algebraic structure that satisfies all of the properties of a ring and every element has a
    multiplicative inverse.
    """
    def is_field(self) -> bool:
        return True



class FieldElement(RingElement):
    """
    Element of a field.
    """

    def __init__(self, field: Field):
        """
        Parameters:
            field (Field): Field this element belongs to.
        """
        self.field = field

    @property
    def ring(self) -> Field:
        return self.field

    @abstractmethod
    def __add__(self, other: 'FieldElement') -> 'FieldElement':
        pass

    @abstractmethod
    def __sub__(self, other: 'FieldElement') -> 'FieldElement':
        pass

    @abstractmethod
    def __mul__(self, other: 'FieldElement') -> 'FieldElement':
        pass

    @abstractmethod
    def __truediv__(self, other: 'FieldElement') -> 'FieldElement':
        pass

    def __floordiv__(self, other: 'FieldElement') -> 'FieldElement':
        return self.__truediv__(other)

    def is_invertible(self) -> bool:
        """
        Determines if the element is invertible.

        Returns:
            bool: Whether the element is invertible.
        """
        return self != self.ring.zero
