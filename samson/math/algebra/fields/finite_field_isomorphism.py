from samson.math.map import Map
from samson.utilities.exceptions import CoercionException

class FiniteFieldIsomorphism(Map):
    def __init__(self, domain: 'Ring', codomain: 'Ring', pre_isomorphism=None):
        if not (domain.p == codomain.p and domain.n == codomain.n):
            raise CoercionException(f"{domain} is not isomorphic to {codomain}")

        F = domain.internal_field
        Q = codomain.internal_field
        w = min(F.quotient.change_ring(Q).roots())
        f = F.random()
        k = f(w)

        for root in Q.quotient.change_ring(F).roots():
            if k(root) == f:
                r = root
                break
        
        self.f_root = w
        self.q_root = r

        super().__init__(domain, codomain, lambda f: codomain(domain(f)(w)), pre_isomorphism, lambda q: domain(codomain(q)(r)))
    

    @property
    def __raw__(self):
        return f'{self.domain.symbol} -> {self.q_root.val(self.codomain.symbol)}'
    

    def __str__(self):
        return f'ϕ: {self.__raw__}'
    

    def __reprdir__(self):
        return ['__raw__', 'domain', 'codomain']
