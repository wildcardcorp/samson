from samson.utilities.general import add_or_increment
from samson.analysis.general import count_items
from functools import reduce
from itertools import combinations, chain

class Factors(object):
    def __init__(self, factors=None):
        self.factors = factors or {}


    def __repr__(self):
        return f'<Factors: {self.factors}>'

    def __str__(self):
        return ' * '.join([f"({fac}){'**' + str(exponent) if exponent > 1 else ''}" for fac, exponent in self.factors.items()])


    def __getitem__(self, idx: int):
        return self.factors[idx]

    def __setitem__(self, idx: int, value):
        self.factors[idx] = value

    def __iter__(self):
        return self.factors.__iter__()


    def __len__(self) -> int:
        return len(self.factors)


    def __add__(self, other: dict) -> 'Factors':
        new_facs = Factors()
        for key in self:
            new_facs.add(key, self[key])

        for key in other:
            new_facs.add(key, other[key])

        return new_facs


    def __truediv__(self, other: 'RingElement') -> 'Factors':
        t = type(other)
        if t is int:
            from samson.math.general import factor
            other = factor(other)
        elif t is not dict:
            other = other.factor()

        return self.difference(other)


    __floordiv__ = __truediv__


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

        if not facs:
            if key and hasattr(key, 'ring'):
                facs[key.ring.one] = 1
            else:
                facs[1] = 1

        return facs


    def expand(self) -> list:
        facs = [[fac]*exponent for fac, exponent in self.factors.items()]
        return [item for sublist in facs for item in sublist]


    def combinations(self, n: int) -> list:
        return (Factors(count_items(c)) for c in combinations(self.expand(), n))


    def all_combinations(self) -> list:
        return chain(*[self.combinations(i) for i in range(1, sum(self.factors.values())+1)])


    def all_divisors(self) -> set:
        return {c.recombine() for c in self.all_combinations()}.union({1})


    def mobius(self) -> int:
        n = self.recombine()
        if (hasattr(n, 'ring') and n == n.ring.one) or n == 1:
            return 1

        elif max(self.factors.values()) > 1:
            return 0

        elif sum(self.factors.values()) % 2:
            return -1

        else:
            return 1


    def recombine(self) -> 'RingElement':
        elem0 = list(self.factors.keys())[0]
        mul   = type(elem0).__mul__
        one   = elem0.ring.one if hasattr(elem0, 'ring') else 1
        return reduce(mul, [p**e for p,e in self.factors.items()], one)
