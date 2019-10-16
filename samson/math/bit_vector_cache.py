from samson.math.algebra.rings.ring import RingElement
from types import FunctionType

class BitVectorCache(object):
    def __init__(self, element: RingElement, start: RingElement, operation: FunctionType, size: int):
        self.element   = element
        self.start     = start
        self.size      = size
        self.cache     = None
        self.operation = operation
        self.rebuild_cache()


    def __repr__(self):
        return f'<BitVectorCache: element={self.element}, size={self.size}>'

    def __str__(self):
        return self.__repr__()


    def __mul__(self, other: int):
        return self.calculate(other)

    def __rmul__(self, other: int):
        return self.calculate(other)

    def __pow__(self, other: int):
        return self.calculate(other)

    def __rpow__(self, other: int):
        return self.calculate(other)


    def rebuild_cache(self):
        """
        Rebuilds the internal cache.
        """
        vec = []
        element = self.element
        op      = self.operation
        for _ in range(self.size):
            vec.append(element)
            element = op(element, element)

        self.cache = vec


    def calculate(self, multiplier: int) -> RingElement:
        """
        Calculates the result using the cache vector.
        """
        cache  = self.cache
        result = self.start
        op     = self.operation
        for idx, bit in enumerate([int(i) for i in bin(multiplier)[2:][::-1]]):
            if bit:
                result = op(result, cache[idx])

        return result
