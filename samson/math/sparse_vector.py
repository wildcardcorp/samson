from sortedcontainers import SortedDict

class SparseVector(object):
    def __init__(self, items: list, zero: int=0):
        if type(items) is dict:
            self.values = SortedDict(items)

        elif type(items) is list:
            if type(items[0]) is tuple:
                self.values = SortedDict(items)
            else:
                self.values = SortedDict({idx: value for idx, value in enumerate(items)})

        else:
            raise Exception("'items' must be dict or list")

        self.zero = zero


    def __repr__(self):
        return f'<SparseVector values={self.values}>'

    def __str__(self):
        return self.__repr__()


    def __hash__(self) -> int:
        return hash(tuple([_ for _ in self.values.items()]))


    def last(self) -> object:
        return self.values.keys()[-1]


    def __getitem__(self, idx: int) -> object:
        try:
            return self.values[idx]
        except KeyError:
            if idx >= len(self):
                raise IndexError('list index out of range')

            return self.zero


    def __setitem__(self, idx: int, obj: object) -> object:
        if obj != self.zero:
            self.values[idx] = obj


    def __len__(self) -> int:
        return self.last() + 1
