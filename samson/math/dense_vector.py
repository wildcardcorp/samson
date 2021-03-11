from samson.utilities.runtime import RUNTIME
from samson.core.base_object import BaseObject
from samson.math.general import gcd
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.fft.all import ntt_convolution, gss_convolution
from types import FunctionType

class DenseVector(BaseObject):
    def __init__(self, values: list, coeff_ring: 'Ring'=None):
        if coeff_ring:
            self.coeff_ring = coeff_ring
        else:
            self.coeff_ring = values[0].ring if hasattr(values[0], 'ring') else ZZ

        self.values = [self.coeff_ring(v) for v in values]


    def shorthand(self, tinyhand: bool=False) -> str:
        if tinyhand:
            str_meth = lambda elem: elem.tinyhand()
        else:
            str_meth = lambda elem: elem.shorthand()

        return "[" + ", ".join([str_meth(val) for val in self.values]) + "]"


    def tinyhand(self) -> str:
        return self.shorthand(True)


    @property
    def __raw__(self):
        return RUNTIME.default_short_printer(self)

    def __reprdir__(self):
        return ['__raw__']


    def __hash__(self) -> int:
        return hash(self.values)

    def __add__(self, other: 'DenseVector') -> 'DenseVector':
        return DenseVector([a+b for a,b in zip(self.values, other.values)])

    def __sub__(self, other: 'DenseVector') -> 'DenseVector':
        return DenseVector([a-b for a,b in zip(self.values, other.values)])

    def __neg__(self) -> 'DenseVector':
        return DenseVector([-a for a in self.values])

    def __mul__(self, other: object) -> 'DenseVector':
        return DenseVector([a*other for a in self.values])


    def __iter__(self):
        return self.values.__iter__()


    def __getitem__(self, idx: object) -> 'RingElement':
        result = self.values[idx]
        if type(idx) is slice:
            return DenseVector(result)
        else:
            return result
    

    def __setitem__(self, idx, value):
        self.values[idx] = value


    def __len__(self):
        return len(self.values)


    def dot(self, other: 'DenseVector') -> object:
        return sum([a*b for a,b in zip(self.values, other.values)], self.coeff_ring.zero)


    def sdot(self) -> object:
        return self.dot(self)


    def proj_coeff(self, other: 'DenseVector') -> object:
        return self.dot(other) / self.sdot()


    def project(self, other: 'DenseVector') -> 'DenseVector':
        return self * self.proj_coeff(other)


    def apply_elementwise(self, func: FunctionType) -> 'DenseVector':
        """
        Applies a function to each element and returns a `DenseVector` of the results.

        Parameters:
            func (func): Function to apply.

        Returns:
            DenseVector: Result DenseVector.
        """
        return DenseVector([func(e) for e in self.values])


    def change_ring(self, ring: 'Ring') -> 'DenseVector':
        """
        Returns a new DenseVector with the coefficients coerced into `ring`.

        Parameters:
            ring (Ring): Ring to embed into.

        Returns:
            DenseVector: Resultant DenseVector.
        """
        return DenseVector(self.values, coeff_ring=ring)


    def convolve(self, other: 'DenseVector') -> 'DenseVector':
        """
        Performs linear convolution between two vectors.

        Parameters:
            other (DenseVector): Other vector to convolve with.

        Returns:
            DenseVector: Convolved vector.
        """
        l_self = len(self)
        for i in range(l_self):
            if self[i]:
                break

        p1_min  = i
        l_other = len(other)

        for i in range(l_other):
            if other[i]:
                break
        
        p2_min = i
        max_deg = max(l_self-p1_min, l_other-p2_min)
        logn    = max_deg.bit_length()
        n       = 2**logn

        vec_a = self[p1_min:]
        vec_b = other[p2_min:]

        # Decide whether to do naive convolution or FFT convo
        if max_deg and max_deg**2 > 10*(3*n*logn+n):
            if self.coeff_ring == ZZ:
                return DenseVector(ntt_convolution(vec_a.values, vec_b.values))

            elif self.coeff_ring == ZZ.fraction_field():
                content_a = gcd(*vec_a.values)
                content_b = gcd(*vec_b.values)

                vec_a_zz = vec_a * ~content_a
                vec_b_zz = vec_b * ~content_b
                vec_c_zz = DenseVector(ntt_convolution(vec_a_zz.values, vec_b_zz.values))

                return vec_c_zz*(content_a*content_b)


            # TODO: Check for Quotient ring
            else:
                return gss_convolution(vec_a.values, vec_b.values).dense_vector()

        else:
            vec = [0]*(len(vec_a) + len(vec_b))
            for i, a in enumerate(vec_a):
                for j, b in enumerate(vec_b):
                    vec[i+j] += a*b
            
            return DenseVector(vec)
