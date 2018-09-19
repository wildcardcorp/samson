from samson.utilities.manipulation import xor_buffs, left_rotate, right_rotate
from samson.utilities.encoding import int_to_bytes

class Bytes(object):
    def __init__(self, bytes):
        self.bytes = bytes


    def __repr__(self):
        return '<Bytes: {}>'.format(str(bytes(self.bytes)))


    def __xor__(self, other):
        if isinstance(other, self.__class__):
            return Bytes(xor_buffs(self.bytes, other.bytes))
        elif isinstance(other, bytes) or isinstance(other, bytearray):
            return Bytes(xor_buffs(self.bytes, other))
        else:
            raise TypeError("unsupported operand type(s) for ^: '{}' and '{}'".format(self.__class__, type(other)))



    def __rxor__(self, other):
        return self.__xor__(other)


    def __getitem__(self, index):
        return Bytes(self.bytes[index])

    
    def __len__(self):
        return len(self.bytes)


    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.bytes == other.bytes
        elif isinstance(other, bytes) or isinstance(other, bytearray):
            return self.bytes == other
        else:
            raise TypeError("unsupported operand type(s) for ==: '{}' and '{}'".format(self.__class__, type(other)))


    def __contains__(self, value):
        return value in self.bytes


    def __gt__(self, other):
        if isinstance(other, self.__class__):
            return self.bytes > other.bytes
        elif isinstance(other, bytes) or isinstance(other, bytearray):
            return self.bytes > other
        else:
            raise TypeError("unsupported operand type(s) for >: '{}' and '{}'".format(self.__class__, type(other)))


    def __ge__(self, other):
        return self.__gt__(other) or self.__eq__(other)


    def __lt__(self, other):
        return not self.__ge__(other)


    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)



    def __and__(self, other):
        self_as_int = int.from_bytes(self.bytes, 'little')

        if isinstance(other, self.__class__):
            return Bytes(int_to_bytes(self_as_int & int.from_bytes(other.bytes, 'little'), 'little'))
        elif isinstance(other, bytes) or isinstance(other, bytearray):
            return Bytes(int_to_bytes(self_as_int & int.from_bytes(other, 'little'), 'little'))
        else:
            raise TypeError("unsupported operand type(s) for 'and': '{}' and '{}'".format(self.__class__, type(other)))


    def __rand__(self, other):
        return self.__and__(other)


    def __or__(self, other):
        self_as_int = int.from_bytes(self.bytes, 'little')

        if isinstance(other, self.__class__):
            return Bytes(int_to_bytes(self_as_int | int.from_bytes(other.bytes, 'little'), 'little'))
        elif isinstance(other, bytes) or isinstance(other, bytearray):
            return Bytes(int_to_bytes(self_as_int | int.from_bytes(other, 'little'), 'little'))
        else:
            raise TypeError("unsupported operand type(s) for 'or': '{}' and '{}'".format(self.__class__, type(other)))


    def __ror__(self, other):
        return self.__or__(other)


    def __add__(self, other):
        if isinstance(other, self.__class__):
            return Bytes(self.bytes + other.bytes)
        elif isinstance(other, bytes) or isinstance(other, bytearray):
            return Bytes(self.bytes + other)
        else:
            raise TypeError("unsupported operand type(s) for +: '{}' and '{}'".format(self.__class__, type(other)))


    def __radd__(self, other):
        return self.__add__(other)



    def lrot(self, amount):
        as_int = int.from_bytes(self.bytes, 'little')
        back_to_bytes = int_to_bytes(left_rotate(as_int, amount), 'little')
        return Bytes(back_to_bytes)


    def rrot(self, amount):
        as_int = int.from_bytes(self.bytes, 'little')
        back_to_bytes = int_to_bytes(right_rotate(as_int, amount), 'little')
        return Bytes(back_to_bytes)