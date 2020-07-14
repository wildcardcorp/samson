from samson.utilities.general import add_or_increment
from samson.analysis.general import count_items
from functools import reduce
from itertools import combinations

class Factors(object):
    def __init__(self, factors=None):
        self.factors = factors or {}


    def __repr__(self):
        return f'<Factors: {self.factors}>'

    def __str__(self):
        return ' * '.join([f"{fac}**{exponent}" for fac, exponent in self.factors.items()])


    def __getitem__(self, idx: int):
        return self.factors[idx]

    def __setitem__(self, idx: int, value):
        self.factors[idx] = value

    def __iter__(self):
        return self.factors.__iter__()


    def __len__(self):
        return len(self.factors)


    def __add__(self, other: dict):
        new_facs = Factors()
        for key in self:
            new_facs.add(key, self[key])

        for key in other:
            new_facs.add(key, other[key])
        
        return new_facs


    def __sub__(self, other: dict):
        return self.difference(other)


    def __getattr__(self, name: str):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = getattr(self.factors, name)

        return attr


    def add(self, factor: 'RingElement', number: int=1):
        add_or_increment(self.factors, factor, number)


    def remove(self, factor: 'RingElement', number: int=1):
        if number >= self.factors[factor]:
            del self.factors[factor]
        else:
            self.factors[factor] -= number


    def difference(self, other: dict) -> 'Factors':
        facs = Factors({})
        for key in self:
            facs[key] = self[key]
            if key in other:
                facs.remove(key, other[key])

        return facs


    def expand(self) -> list:
        facs = [[fac]*exponent for fac, exponent in self.factors.items()]
        return [item for sublist in facs for item in sublist]


    def combinations(self, n: int):
        return (Factors(count_items(c)) for c in combinations(self.expand(), n))


    def recombine(self):
        elem0 = list(self.factors.keys())[0]
        mul   = type(elem0).__mul__
        one   = elem0.ring.one if hasattr(elem0, 'ring') else 1
        return reduce(mul, [p**e for p,e in self.factors.items()], one)
