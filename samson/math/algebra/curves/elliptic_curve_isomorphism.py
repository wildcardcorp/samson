from samson.math.algebra.curves.weierstrass_curve import EllipticCurve, WeierstrassPoint
from samson.math.map import Map
from samson.utilities.exceptions import NoSolutionException
from samson.utilities.runtime import RUNTIME
from samson.core.base_object import BaseObject

class EllipticCurveIsomorphism(Map):
    def __init__(self, domain: EllipticCurve, codomain: EllipticCurve, u, r, s, t, pre_isomorphism: 'Map'=None):
        self.domain   = domain
        self.codomain = codomain
        self.u = u
        self.r = r
        self.s = s
        self.t = t
        self.pre_isomorphism = pre_isomorphism


    def __reprdir__(self):
        return ['domain', 'codomain', 'u', 'r', 's', 't']


    def __str__(self):
        return f'ϕ: {self.true_domain} (u={self.u}, r={self.r}, s={self.s}, t={self.t}) -> {self.codomain}'


    def map_func(self, P):
        if not P:
            return self.codomain.zero

        x, y = P.x, P.y
        x   -= self.r
        y   -= (self.s*x+self.t)
        return self.codomain(x/self.u**2, y/self.u**3)


    def __hash__(self):
        return hash((self.domain, self.codomain, self.u, self.r, self.s, self.t, self.pre_isomorphism))


    @staticmethod
    def identity(domain, codomain):
        R = domain.ring
        return EllipticCurveIsomorphism(domain, codomain, R.one, R.zero, R.zero, R.zero)


    def is_identity(self):
        return self.u == self.u.ring.one and not any([self.r, self.s, self.t])


    def __invert__(self):
        u, r, s, t = self.u, self.r, self.s, self.t
        return EllipticCurveIsomorphism(self.codomain, self.domain, u=1/u, r=-r/u**2, s=-s/u, t=(r*s-t)/u**3)


    def __mul__(self, other):
        us, rs, ss, ts = self.u, self.r, self.s, self.t
        uo, ro, so, to = other.u, other.r, other.s, other.t
        return EllipticCurveIsomorphism(self.domain, self.codomain, u=us*uo, r=(us**2) * ro + rs, s=us*so + ss, t=(us**3) * to + ss * (us**2) * ro + ts)


    def __truediv__(self, other):
        return self * ~other


    def __neg__(self):
        return EllipticCurveIsomorphism(self.domain, self.codomain, u=-self.u, r=self.r, s=self.s, t=self.t)
