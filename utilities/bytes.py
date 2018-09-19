from samson.utilities.manipulation import xor_buffs, left_rotate, right_rotate, get_blocks
from samson.utilities.encoding import int_to_bytes
from samson.utilities.general import rand_bytes

class Bytes(bytearray):

    @staticmethod
    def wrap(bytes_like):
        if isinstance(bytes_like, Bytes):
            return bytes_like
        else:
            return Bytes(bytes_like)

    
    @staticmethod
    def random(size=16):
        return Bytes(rand_bytes(size))


    def __repr__(self):
        return '<Bytes: {}>'.format(str(bytes(self)))


    def __xor__(self, other):
        return Bytes(xor_buffs(self, other))


    def __rxor__(self, other):
        return self.__xor__(other)


    def __getitem__(self, index):
        result = bytearray.__getitem__(self, index)
        if type(result) is int:
            return result
        else:
            return Bytes(result)
        

    def __and__(self, other):
        self_as_int = int.from_bytes(self, 'little')
        return Bytes(int_to_bytes(self_as_int & int.from_bytes(other, 'little'), 'little'))

    def __rand__(self, other):
        return self.__and__(other)


    def __or__(self, other):
        self_as_int = int.from_bytes(self, 'little')
        return Bytes(int_to_bytes(self_as_int | int.from_bytes(other, 'little'), 'little'))


    def __ror__(self, other):
        return self.__or__(other)


    def __add__(self, other):
        return Bytes(bytearray.__add__(self, other))


    def __radd__(self, other):
        return Bytes(bytearray(other).__add__(self))



    def lrot(self, amount, bits=None):
        as_int = int.from_bytes(self, 'little')

        if not bits:
            bits = len(self) * 8

        back_to_bytes = int_to_bytes(left_rotate(as_int, amount, bits), 'little')
        return Bytes(back_to_bytes)


    def rrot(self, amount, bits=None):
        as_int = int.from_bytes(self, 'little')

        if not bits:
            bits = len(self) * 8
        back_to_bytes = int_to_bytes(right_rotate(as_int, amount, bits), 'little')
        return Bytes(back_to_bytes)



    def chunk(self, size, allow_partials=False):
        for block in get_blocks(self, size, allow_partials):
            yield block