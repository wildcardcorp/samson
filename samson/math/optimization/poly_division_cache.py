from samson.math.symbols import Symbol
from samson.math.algebra.rings.ring import RingElement, set_precendence_override


class PolyDivisionCache(RingElement):

    def __init__(self, divisor, prec):
        self.divisor = divisor
        self.ring    = divisor.ring

        g_hat  = divisor.reverse()
        T      = divisor.coeff_ring[[Symbol('y')]]
        T.prec = prec

        self.T = T
        self.g = ~T(g_hat)


    def __getattribute__(self, name):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = object.__getattribute__(self.divisor, name)

        return attr


    @set_precendence_override(True)
    def __rfloordiv__(self, f):
        n, m = f.degree(), self.divisor.degree()
        if not f or n < m:
            return self.ring.zero

        T      = self.T.copy()
        T.prec = n-m+1
        res    = (T(f.reverse())*T(self.g)).val.reverse()
        return res << (n-m-res.degree())


    @set_precendence_override(True)
    def __relemmod__(self, f):
        _q, r = self.__rdivmod__(f)
        return r


    @set_precendence_override(True)
    def __relemdivmod__(self, f):
        if f.degree() > self.T.prec:
            return f.__elemdivmod__(self.divisor)

        q = self.__rfloordiv__(f)
        return q, f-q*self.divisor

    __rmod__ = __relemmod__
