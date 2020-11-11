from samson.utilities.general import binary_search_list
from sortedcontainers import SortedDict
from copy import copy

class SparseVector(object):
    """
    Sparse vector implementation. Saves on memory when representing high-dimensional vectors with many zeroes.
    """

    def __init__(self, items: list, zero: object=None, allow_virtual_len: bool=True):
        """
        Parameters:
            items  (list): Items as dictionary, list of tuples, or just a list.
            zero (object): The zero element. This element will not be stored.
        """
        if zero is None:
            if hasattr(items[0], 'ring'):
                zero = items[0].ring.zero
            else:
                zero = 0

        not_empty = len(items)


        if type(items) is dict:
            self.values = SortedDict({k:v for k,v in items.items() if v != zero})
            length = list(items.keys())[-1] if not_empty else 0

        elif type(items) is list:
            if len(items) == 0 or type(items[0]) is tuple:
                self.values = SortedDict([(k, v) for k,v in items if v != zero])
                length = items[-1][0] if not_empty else 0
            else:
                self.values = SortedDict({idx: value for idx, value in enumerate(items) if value != zero})
                length = not_empty

        else:
            raise TypeError("'items' must be dict or list")

        for key in self.values.keys():
            if not type(key) is int:
                raise TypeError('idx must be an integer')


        self.zero = zero
        self.allow_virtual_len = allow_virtual_len
        self.virtual_len = length


    def __repr__(self):
        return f'<SparseVector: values={self.values}, virtual_len={self.virtual_len}>'

    def __str__(self):
        return self.__repr__()


    def __hash__(self) -> int:
        return hash(tuple([_ for _ in self.values.items()]))


    @staticmethod
    def wrap(items, *args, **kwargs):
        if type(items) is SparseVector:
            return items

        return SparseVector(items, *args, **kwargs)



    def list(self) -> list:
        if len(self):
            return [self[i] for i in range(len(self))]
        else:
            return []


    def trim(self):
        self.virtual_len = self.last() + 1 if self.sparsity else 0


    def last(self) -> int:
        """
        Returns the index of the last element.

        Returns:
            int: Index of last element.
        """
        return self.values.keys()[-1] if self.values else 0



    def __iter__(self):
        for item in self.values.items():
            yield item


    def map(self, func):
        vec = SparseVector([func(idx, val) for idx, val in self], zero=self.zero, allow_virtual_len=self.allow_virtual_len)
        vec.virtual_len = max(self.virtual_len, vec.last()+1)
        return vec


    def __getitem__(self, idx: int) -> object:
        try:
            if type(idx) is slice:
                items  = self.values.items()
                length = len(items)
                key    = lambda item: item[0]

                start_not_none = idx.start is not None
                end_not_none   = idx.stop is not None

                if start_not_none and idx.start < 0 or end_not_none and idx.stop < 0:
                    raise ValueError("Negative slices not supported for SparseVectors")

                start = binary_search_list(items, idx.start, key=key, fuzzy=True) if start_not_none else 0
                end   = binary_search_list(items, idx.stop, key=key, fuzzy=True) if end_not_none else length

                if end < 0:
                    end = 0

                selected_items = items[start:end:idx.step]

                # Need to normalize indices so they start at 0
                req_start = idx.start or 0
                req_stop  = len(self) if idx.stop is None else idx.stop
                selected_items = [(i-req_start, val) for i,val in selected_items]

                new_vec = SparseVector(selected_items, self.zero, allow_virtual_len=self.allow_virtual_len)


                # Calculate 'new_vec' length
                calcd_len = (req_stop - req_start) // (idx.step or 1)
                new_vec.virtual_len = max(min(calcd_len, self.len()), 0)

                return new_vec
            else:
                if idx < 0:
                    idx += self.len()

                return self.values[idx]
        except KeyError:
            return self.zero



    def __setitem__(self, idx: int, obj: object) -> object:
        if not type(idx) is int:
            raise ValueError('idx must be an integer')

        if obj == self.zero:
            if idx in self.values:
                del self.values[idx]

        else:
            self.values[idx] = obj

        if idx >= self.len():
            self.virtual_len = idx+1



    def __contains__(self, item: 'RingElement') -> bool:
        return item in self.values


    def __eq__(self, other: 'SparseVector') -> bool:
        return self.values == other.values


    def __len__(self) -> int:
        return self.len()


    def append(self, item):
        self[self.len()] = item


    @property
    def sparsity(self):
        return len(self.values)


    def __add__(self, other):
        new_self = copy(self)

        if type(other) is SparseVector:
            last = len(new_self)
            new_self.values.update({k+last:v for k,v in other.values.items()})
            new_self.virtual_len += other.virtual_len

        else:
            for item in other:
                new_self.append(item)

        return new_self


    def len(self) -> int:
        """
        Calculate the length of the `SparseVector`. Use this instead of __len__ to prevent
        integer overflow problems.
        """
        return self.virtual_len if self.allow_virtual_len else (self.last() + 1 if self.values.keys() else 0)


    def vec_add(self, other) -> 'SparseVector':
        vec = SparseVector([], zero=self.zero)
        for idx, coeff in self:
            vec[idx] = coeff + other[idx]

        for idx, coeff in other:
            if not idx in self:
                vec[idx] = coeff

        vec.virtual_len = self.virtual_len
        return vec
