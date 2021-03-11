from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.symbols import Symbol
from samson.math.fft.gss import _convolution
import unittest

x = Symbol('x')
P = ZZ[x]
p1 = 10*x**2000-3*x**3+1
p2 = -6*x**1000 + 5*x**1 + x

class FFTTestCase(unittest.TestCase):
    def test_perf(self):
        _convolution(p1.coeffs, p2.coeffs)
