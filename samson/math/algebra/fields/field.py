from abc import abstractmethod #ABC,
from samson.math.algebra.rings.ring import RingElement, Ring

class Field(Ring):
    pass


class FieldElement(RingElement):
    def __init__(self, field: Field):
        self.field = field
    
    @property
    def ring(self) -> Field:
        return self.field

    @abstractmethod
    def __add__(self, other: object) -> object:
        pass

    @abstractmethod
    def __sub__(self, other: object) -> object:
        pass

    @abstractmethod
    def __mul__(self, other: object) -> object:
        pass

    @abstractmethod
    def __truediv__(self, other: object) -> object:
        pass

    def __floordiv__(self, other: object) -> object:
        return self.__truediv__(other)