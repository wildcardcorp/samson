from samson.math.general import newton_method_sizes
from samson.math.symbols import Symbol
from samson.core.base_object import BaseObject

class EllipticCurveFormalGroup(BaseObject):
    def __init__(self, curve):
        self.curve = curve


    def w(self, prec=20):
        z = Symbol('z')
        R = self.curve.ring
        P = R[[z]]
        w = z**3
        a,b = R(self.curve.a), R(self.curve.b)


        for k in newton_method_sizes(prec):
            if w.degree() < k:
                P.prec = k
                n = (-w**2*a*z - w**3*2*b + z**3)
                d = (w*z*-2*a - w**2*3*b + 1)

                w = (n/d)

        return w


    def y(self, prec=20):
        ww = self.w(prec+6)
        y = -(~ww)
        return y.truncate(prec)


    def x(self, prec=20):
        yy = self.y(prec)
        t  = yy.ring.ring.symbol
        return (yy*-t).truncate(prec)



    def differential(self, prec=20):
        xx = self.x(prec+1)
        yy = self.y(prec+1)
        xprime = xx.derivative()
        g = xprime / (yy*2)
        return g.truncate(prec)


    def log(self, prec=20):
        return self.differential(prec-1).integral()
