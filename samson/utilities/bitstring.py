from samson.utilities.manipulation import get_blocks, transpose, stretch_key
from samson.utilities.general import rand_bytes
from samson.utilities.bytes import Bytes
import math
from collections import UserString

class Bitstring(UserString):
    def __init__(self, value, byteorder='big'):
        if type(value) is bytes or type(value) is bytearray or type(value) is Bytes:
            value = int.from_bytes(value, byteorder)
        
        if type(value) is int:
            value = bin(value)[2:]


        if not all([bit in ['0', '1'] for bit in str(value)]):
            raise Exception("Bitstrings can only contain 1's or 0's.")

        super().__init__(value)
        self.byteorder = byteorder


    def _format_return(self, value):
        return Bitstring(str(Bitstring(value, 'big').zfill(len(self))), self.byteorder)#.zfill(len(self))


    @staticmethod
    def wrap(str_like, byteorder='big'):
        if isinstance(str_like, Bitstring):
            return str_like
        else:
            return Bitstring(str_like, byteorder=byteorder)

    
    @staticmethod
    def random(size=16, byteorder='big'):
        return Bitstring(rand_bytes(math.ceil(size / 8)), byteorder=byteorder)[:size]


    def __repr__(self):
        return f'<Bitstring: {" ".join([str(chunk) for chunk in self.zfill(math.ceil(max(1, len(self)) / 8) * 8).chunk(8)])}, byteorder={self.byteorder}>'


    # Byte order will be the downfall of humanity.
    def _clean_byteorder(self, value):
        value.byteorder = 'big'
        return value.int()



    def __xor__(self, other):
        other = Bitstring.wrap(other, self.byteorder).bytes()
        result = self._clean_byteorder(self.bytes() ^ other)
        return self._format_return(result)


    def __rxor__(self, other):
        return self.__xor__(other)


    def __getitem__(self, index):
        return Bitstring(UserString.__getitem__(self, index), self.byteorder)
        

    def __and__(self, other):
        other = Bitstring.wrap(other, self.byteorder).bytes()
        result = self._clean_byteorder(self.bytes() & other)
        return self._format_return(result)


    def __rand__(self, other):
        return self.__and__(other)


    def __or__(self, other):
        other = Bitstring.wrap(other, self.byteorder).bytes()
        result = self._clean_byteorder(self.bytes() | other)
        return self._format_return(result)


    def __ror__(self, other):
        return self.__or__(other)


    def __add__(self, other):
        return Bitstring(UserString.__add__(self, other), self.byteorder)


    def __radd__(self, other):
        return Bitstring(UserString(other).__add__(self), self.byteorder)


    def __lshift__(self, num):
        return self._format_return(self.bytes() << num)


    def __rshift__(self, num):
        return self._format_return(self.bytes() >> num)


    def __invert__(self):
        max_val = 2 ** len(self) - 1
        return self._format_return(max_val - self.int())


    def lrot(self, amount, bits=None):
        return self._format_return(self.bytes().lrot(amount, bits=bits))



    def rrot(self, amount, bits=None):
        return self._format_return(self.bytes().rrot(amount, bits=bits))


    def chunk(self, size, allow_partials=False):
        return get_blocks(self, size, allow_partials)


    def transpose(self, size):
        return self._format_return(''.join(transpose(str(self), size)))


    def zfill(self, size):
        zeroes = max(size - len(self), 0) * '0'
        if self.byteorder == 'big':
            new_bitstring = zeroes + self
        else:
            new_bitstring = self + zeroes

        return Bitstring(new_bitstring, self.byteorder)



    def stretch(self, size, offset=0):
        return self._format_return(stretch_key(self, size, offset))

    
    def to_int(self):
        return self.bytes().int()


    def int(self):
        return self.to_int()

    
    def to_bytes(self):
        return Bytes([int(str(chunk), 2) for chunk in self.zfill(self.byte_length()).chunk(8, allow_partials=True)], self.byteorder)

    
    def bytes(self):
        return self.to_bytes()


    def byte_length(self):
        return math.ceil(len(self) / 8)