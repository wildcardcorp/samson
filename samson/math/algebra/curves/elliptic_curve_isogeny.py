from samson.math.algebra.curves.weierstrass_curve import EllipticCurve, WeierstrassPoint
from samson.math.map import Map
from samson.utilities.exceptions import NoSolutionException
from samson.utilities.runtime import RUNTIME
from samson.core.base_object import BaseObject

class EllipticCurveIsogeny(Map):
    def __init__(self, curve: EllipticCurve, kernel: WeierstrassPoint, pre_isomorphism: 'EllipticCurveIsogeny'=None):
        self.curve  = curve
        self.kernel = kernel
        self.points = [kernel*i for i in range(1, kernel.order())]
        self.pre_isomorphism = pre_isomorphism
        self.map_func = self._rat_map
        self.codomain = self._get_codomain()


    def __reprdir__(self):
        return ['curve', 'kernel']


    @property
    def domain(self):
        return self.curve



    def _get_codomain(self) -> EllipticCurve:
        a, b = self.curve.a, self.curve.b
        w, v = 0, 0

        for Q in self.points:
            x, y = Q.x, Q.y
            gx = x**2*3 + a
            gy = y*-2
            vQ = gx*2
            uQ = gy**2

            v += vQ
            w += uQ + x*vQ


        E2 = EllipticCurve(a-v*5/2, b-w*7/2)
        E2.cardinality_cache = self.curve.order()
        return E2


    def _rat_map(self, P: WeierstrassPoint) -> WeierstrassPoint:
        E = self.codomain
        x = P.x + sum((P+Q).x - Q.x for Q in self.points)
        y = P.y + sum((P+Q).y - Q.y for Q in self.points)
        if x or y:
            return E(x, y)

        # This might be in the kernel. (0, 0) != PAF, so we need to check
        else:
            try:
                Q = E(x)
                if Q.y == y:
                    return Q
                elif (-Q).y == y:
                    return -Q

            except NoSolutionException:
                pass

            return E.zero
