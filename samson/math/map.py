from samson.core.base_object import BaseObject

class Map(BaseObject):
    def __init__(self, domain: 'Ring', codomain: 'Ring', map_func: 'FunctionType', pre_isomorphism: 'Map'=None):
        self.domain   = domain
        self.codomain = codomain
        self.map_func = map_func
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


    def __call__(self, element):
        if self.pre_isomorphism:
            element = self.pre_isomorphism(element)
        
        return self.map_func(element)
