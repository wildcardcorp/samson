from samson.core.base_object import BaseObject
from samson.utilities.runtime import RUNTIME
from samson.utilities.exceptions import NotInvertibleException

class Map(BaseObject):
    def __init__(self, domain: 'Ring', codomain: 'Ring', map_func: 'FunctionType', pre_isomorphism: 'Map'=None, inv_map: 'FunctionType'=None):
        self.domain   = domain
        self.codomain = codomain
        self.map_func = map_func
        self.inv_map = inv_map
        self.pre_isomorphism = pre_isomorphism
    

    def __reprdir__(self):
        return ['true_domain', 'domain', 'codomain']


    def __str__(self):
        return f'ϕ: {self.true_domain} -> {self.codomain}'


    @property
    def true_domain(self):
        if self.pre_isomorphism:
            return self.pre_isomorphism.true_domain
        else:
            return self.domain


    @RUNTIME.global_cache()
    def __call__(self, element):
        if self.pre_isomorphism:
            element = self.pre_isomorphism(element)
        
        return self.map_func(element)


    def __hash__(self):
        return hash((self.domain, self.codomain, self.map_func))


    def is_endomorphism(self):
        return self.domain == self.codomain


    @RUNTIME.global_cache()
    def degree(self):
        if not self.is_endomorphism():
            raise ValueError('Cannot find the degree of a non-endomorphism')
        
        P = self.domain.random()
        Q = self(P)
        i = 1

        while Q != P:
            Q  = self(Q)
            i += 1

        return i



    def __invert__(self):
        if self.inv_map:
            return Map(self.codomain, self.domain, self.inv_map, inv_map=self.map_func)
        else:
            raise NotInvertibleException("Map is uninvertible", parameters={'a': self})
