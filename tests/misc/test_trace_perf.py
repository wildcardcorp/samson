from samson.math.all import ZZ, EllipticCurve, frobenius_trace_mod_l
import unittest

class TracePerfTestCase(unittest.TestCase):
    def test_perf(self):
        R = ZZ/ZZ(796154926807035870504347582311)
        a = R(796154926807035870500956487527)
        b = R(77986137112576)

        E = EllipticCurve(a, b)

        for _ in range(5):
            frobenius_trace_mod_l(E, 7)
