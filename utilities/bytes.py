from samson.utilities.manipulation import xor_buffs, left_rotate, right_rotate, get_blocks, transpose, stretch_key
from samson.utilities.encoding import int_to_bytes
from samson.utilities.general import rand_bytes

class Bytes(bytearray):
    def __init__(self, bytes_like, byteorder='big'):
        super().__init__(bytes_like)
        self.byteorder = byteorder

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
        return Bytes(xor_buffs(self, other), self.byteorder)


    def __rxor__(self, other):
        return self.__xor__(other)


    def __getitem__(self, index):
        result = bytearray.__getitem__(self, index)
        if type(result) is int:
            return result
        else:
            return Bytes(result, self.byteorder)
        

    def __and__(self, other):
        self_len = len(self)
        self_as_int = int.from_bytes(self, self.byteorder)
        return Bytes(int.to_bytes(self_as_int & int.from_bytes(other, self.byteorder), self_len, self.byteorder), self.byteorder)


    def __rand__(self, other):
        return self.__and__(other)


    def __or__(self, other):
        self_as_int = int.from_bytes(self, self.byteorder)
        return Bytes(int_to_bytes(self_as_int | int.from_bytes(other, self.byteorder), self.byteorder), self.byteorder)


    def __ror__(self, other):
        return self.__or__(other)


    def __add__(self, other):
        return Bytes(bytearray.__add__(self, other), self.byteorder)


    def __radd__(self, other):
        return Bytes(bytearray(other).__add__(self), self.byteorder)


    def __lshift__(self, num):
        as_int = int.from_bytes(self, self.byteorder)
        return Bytes(int.to_bytes((as_int << num) %  (2**(len(self) * 8)), len(self), self.byteorder))


    def __rshift__(self, num):
        as_int = int.from_bytes(self, self.byteorder)
        return Bytes(int.to_bytes((as_int >> num) % (2**(len(self) * 8)), len(self), self.byteorder))


    def lrot(self, amount, bits=None):
        as_int = int.from_bytes(self, self.byteorder)

        if not bits:
            bits = len(self) * 8

        back_to_bytes = int.to_bytes(left_rotate(as_int, amount, bits), bits // 8, self.byteorder)
        return Bytes(back_to_bytes, self.byteorder)


    def rrot(self, amount, bits=None):
        as_int = int.from_bytes(self, self.byteorder)

        if not bits:
            bits = len(self) * 8
        back_to_bytes = int.to_bytes(right_rotate(as_int, amount, bits), bits // 8, self.byteorder)
        return Bytes(back_to_bytes, self.byteorder)



    def chunk(self, size, allow_partials=False):
        return get_blocks(self, size, allow_partials)


    def transpose(self, size):
        return Bytes(b''.join(transpose(self, size)), self.byteorder)


    def zfill(self, size):
        as_int = int.from_bytes(self, self.byteorder)
        return Bytes(int.to_bytes(as_int, size, self.byteorder))


    def stretch(self, size, offset=0):
        return Bytes(stretch_key(self, size, offset), self.byteorder)