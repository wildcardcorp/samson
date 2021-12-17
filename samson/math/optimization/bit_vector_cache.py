from samson.math.algebra.rings.ring import RingElement
from samson.core.base_object import BaseObject
from samson.math.general import product
from samson.encoding.general import fast_naf
from types import FunctionType

class BitVectorCache(BaseObject):
    def __init__(self, element: RingElement, start: RingElement, operation: FunctionType, size: int):
        self.element   = element
        self.start     = start
        self.size      = size
        self.cache     = None
        self.operation = operation
        self.rebuild_cache()


    def __reprdir__(self):
        return ['element', 'size']


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



class AdditiveBitVectorCache(BitVectorCache):
    def calculate(self, x: int) -> RingElement:
        """
        Calculates the result using the cache vector.
        """
        cache = self.cache
        res   = [self.start]
        res2  = []

        np, nm = fast_naf(x)

        i = 0
        while np != 0:
            if np & 1:
                res.append(cache[i])
            elif nm & 1:
                res2.append(cache[i])

            np >>= 1
            nm >>= 1
            i   += 1

        return sum(res, self.element.ring.zero) - sum(res2, self.element.ring.zero)
