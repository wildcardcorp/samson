from samson.utilities.general import binary_search
from sortedcontainers import SortedDict

class SparseVector(object):
    """
    Sparse vector implementation. Saves on memory when representing high-dimensional vectors with many zeroes.
    """

    def __init__(self, items: list, zero: object=0):
        """
        Parameters:
            items  (list): Items as dictionary, list of tuples, or just a list.
            zero (object): The zero element. This element will not be stored.
        """
        if type(items) is dict:
            self.values = SortedDict({k:v for k,v in items.items() if v != zero})

        elif type(items) is list:
            if len(items) == 0 or type(items[0]) is tuple:
                self.values = SortedDict([(k, v) for k,v in items if v != zero])
            else:
                self.values = SortedDict({idx: value for idx, value in enumerate(items) if value != zero})

        else:
            raise Exception("'items' must be dict or list")

        self.zero = zero


    def __repr__(self):
        return f'<SparseVector values={self.values}>'

    def __str__(self):
        return self.__repr__()


    def __hash__(self) -> int:
        return hash(tuple([_ for _ in self.values.items()]))


    def last(self) -> int:
        """
        Returns the index of the last element.

        Returns:
            int: Index of last element.
        """
        return self.values.keys()[-1]


    def __iter__(self):
        for item in self.values.items():
            yield item


    def __getitem__(self, idx: int) -> object:
        try:
            if type(idx) is slice:
                items  = self.values.items()
                length = len(items)
                key    = lambda item: item[0]

                start_not_none = idx.start is not None
                end_not_none   = idx.stop is not None

                if start_not_none and idx.start < 0 or end_not_none and idx.stop < 0:
                    raise Exception("Negative slices not supported for SparseVectors")

                start   = binary_search(items, idx.start, key=key, fuzzy=True) if start_not_none else 0
                end     = binary_search(items, idx.stop, key=key, fuzzy=True) if end_not_none else length

                if end < 0:
                    end = 0

                new_vec = SparseVector(items[start:end:idx.step], self.zero)

                return new_vec
            else:
                if idx < 0:
                    idx += self.len()

                return self.values[idx]
        except KeyError:
            return self.zero


    def __setitem__(self, idx: int, obj: object) -> object:
        if obj == self.zero:
            if idx in self.values:
                del self.values[idx]
        else:
            self.values[idx] = obj


    def __contains__(self, item: object):
        return item in self.values


    def __eq__(self, other: object) -> bool:
        return self.values == other.values


    def __len__(self) -> int:
        return self.len()


    def len(self) -> int:
        """
        Calculate the length of the `SparseVector`. Use this instead of __len__ to prevent
        integer overflow problems.
        """
        return self.last() + 1
