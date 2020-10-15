from samson.utilities.general import add_or_increment
from samson.analysis.general import count_items
from functools import reduce
from itertools import combinations, chain
from sortedcontainers import SortedDict

class Factors(object):
    def __init__(self, factors=None):
        self.factors = SortedDict(factors or {})


    def __repr__(self):
        return f'<Factors: {self.factors}>'

    def __str__(self):
        facs = list(self.factors.items())
        if facs and type(facs[0][0]) is int:
            fac_format = "{fac}"
        else:
            fac_format = "({fac})"

        return ' * '.join([f"{fac_format.format(fac=fac)}{'**' + str(exponent) if exponent > 1 else ''}" for fac, exponent in facs])


    def __getitem__(self, idx: int):
        return self.factors[idx]

    def __setitem__(self, idx: int, value):
        self.factors[idx] = value

    def __iter__(self):
        return self.factors.__iter__()


    def __len__(self) -> int:
        return len(self.factors)


    def __hash__(self):
        return hash(self.recombine())


    def _compare(self, other, func):
        t = type(other)

        if t in [dict, SortedDict]:
            other = Factors(other)

        elif t is not Factors:
            return func(self.recombine(), other)

        return func(self.recombine(), other.recombine())


    def __eq__(self, other):
        return self._compare(other, lambda a, b: a == b)


    def __lt__(self, other):
        return self._compare(other, lambda a, b: a < b)


    def __gt__(self, other):
        return self._compare(other, lambda a, b: a > b)


    def __ge__(self, other):
        return self._compare(other, lambda a, b: a >= b)


    def __le__(self, other):
        return self._compare(other, lambda a, b: a <= b)



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
            from samson.math.factorization.general import factor
            other = factor(other)

        elif t not in [Factors, dict, SortedDict]:
            other = other.factor()

        return self.difference(other)


    __mul__ = __add__
    __floordiv__ = __truediv__
    __sub__ = __truediv__


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


    def number_of_factors(self) -> int:
        return sum(self.factors.values())


    def all_combinations(self) -> list:
        return chain(*[self.combinations(i) for i in range(1, self.number_of_factors()+1)])


    def all_divisors(self) -> set:
        return {c.recombine() for c in self.all_combinations()}.union({1})


    def mobius(self) -> int:
        n = self.recombine()
        if (hasattr(n, 'ring') and n == n.ring.one) or n == 1:
            return 1

        elif max(self.factors.values()) > 1:
            return 0

        elif self.number_of_factors() % 2:
            return -1

        else:
            return 1


    def recombine(self) -> 'RingElement':
        if not self.factors:
            return 1

        elem0 = list(self.factors.keys())[0]
        mul   = type(elem0).__mul__
        one   = elem0.ring.one if hasattr(elem0, 'ring') else 1
        return reduce(mul, [p**e for p,e in self.factors.items()], one)
