from samson.core.base_object import BaseObject
from enum import Enum as _Enum, IntFlag as _IntFlag
import math

SIZE_ENC = 2

def int_to_bytes(val):
    return int.to_bytes(val, (val.bit_length() + 7) // 8, 'big')

def pack_len(val):
    return int.to_bytes(len(val), SIZE_ENC, 'big')

def unpack_len(data):
    return data[SIZE_ENC:], int.from_bytes(data[:SIZE_ENC], 'big')


class ByteWriter(object):
    def __init__(self, data=None) -> None:
        self.data = data or b''
    
    def write(self, buffer):
        self.data += buffer


class BitWriter(object):
    def __init__(self) -> None:
        self.data = ''

    def write(self, buffer, size):
        bits = bin(int.from_bytes(buffer, 'big'))[2:].zfill(size)
        self.data += bits



class ByteConsumer(object):
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.idx  = 0
    
    def next(self, bits):
        num_bytes = math.ceil(bits / 8)
        result    = self.data[self.idx:self.idx+num_bytes]
        self.idx += num_bytes
        return result, num_bytes


class BitConsumer(object):
    def __init__(self, data: bytes) -> None:
        self.data = bin(int.from_bytes(data, 'big'))[2:]
        self.data = self.data.zfill((-len(self.data) % 8)+len(self.data))
        self.idx  = 0


    def is_done(self):
        return self.idx >= len(self.data)
    
    def next(self, bits):
        if self.idx < len(self.data):
            result    = self.data[self.idx:self.idx+bits]
            self.idx += bits
            if self.idx > len(self.data):
                bits = len(self.data) % bits
            return int.to_bytes(int(result, 2), math.ceil(bits / 8), 'big'), bits
        else:
            return b'', 0


class Subscriptable(object):
    def __getitem__(self, idx):
        return self.__class__(self.val[idx])


class TypedClass(type):
    def __getattribute__(self, __name: str):
        if __name in self.__annotations__:
            return self.__annotations__[__name]
        return super().__getattribute__(__name)


class Primitive(object):
    def native(self):
        return self.val


class Serializable(BaseObject):
    def __init__(self, *args, **kwargs) -> None:
        for (k, t), v in zip(self.__annotations__.items(), args):
            if type(v) is not t:
                v = t(v)

            setattr(self, k, v)

        for k, v in kwargs.items():
            t = self.__annotations__[k]
            if type(v) is not t:
                v = t(v)

            setattr(self, k, v)


    def serialize(self):
        data = b''
        for _,v in self.__dict__.items():
            data += v.serialize()
        
        return data


    @classmethod
    def deserialize(cls, data: bytes):
        if hasattr(data, 'native'):
            data = data.native()
        
        return cls._deserialize(data)


    @classmethod
    def _deserialize(cls, data):
        objs = []
        for k, v in cls.__annotations__.items():
            data, obj = v.deserialize(data)
            objs.append(obj)

        return data, cls(*objs)


    @classmethod
    def from_bytes(cls, data):
        return cls.deserialize(data)[1]
    

    def native(self):
        return self


    def __bytes__(self):
        return self.serialize()
    

    def __eq__(self, other):
        return type(self) == type(other) and self.__dict__ == other.__dict__


    def __iter__(self):
        return tuple(self.__dict__.values()).__iter__()


    def __hash__(self) -> int:
        return hash((self.__class__, *list(self)))


    def __lt__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val < other


    def __gt__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val > other


    def __le__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val <= other


    def __ge__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val >= other


    def __eq__(self, other):
        s, o = self, other
        if hasattr(other, 'native'):
            o = other.native()
            s = self.native()

        elif hasattr(other, 'val'):
            o = other.val
            s = self.val
        
        else:
            return self.native() == o
        
        return (not issubclass(type(s), Serializable) and s == o) or (type(s) == type(o) and s.__dict__ == o.__dict__)


class SubtypableMeta(type):
    TYPED_CLS = None

    def __getitem__(cls, l_type):
        class Inst(cls.TYPED_CLS or cls):
            pass

        Inst.__name__ = f'{cls.__name__}[{l_type.__name__}]'
        Inst.SUBTYPE = l_type
        return Inst


class Subtypable(Serializable, metaclass=SubtypableMeta):
    pass



class SizableMeta(type):
    SIZABLE_CLS = None

    def __getitem__(cls, size):
        class Inst(cls.SIZABLE_CLS):
            pass

        Inst.__name__ = f'{cls.__name__}[{size}]'
        Inst.SIZE = size
        return Inst



class Sizable(Serializable, metaclass=SizableMeta):
    pass


class FixedInt(Primitive, Serializable):
    SIZE   = None
    SIGNED = False
    val: int

    def __init__(self, val) -> None:
        super().__init__(val)
        if self.val.bit_length() > self.SIZE:
            raise OverflowError("Int too large")

    def serialize(self):
        return int.to_bytes(self.val, self.SIZE // 8, 'big', signed=self.SIGNED)

    @classmethod
    def _deserialize(cls, data):
        return data[cls.SIZE // 8:], cls(int.from_bytes(data[:cls.SIZE // 8], 'big', signed=cls.SIGNED))


    def __int__(self):
        return self.val



class SignedFixedInt(FixedInt):
    SIGNED = True


class Int8(SignedFixedInt):
    SIZE = 8


class Int16(SignedFixedInt):
    SIZE = 16


class Int32(SignedFixedInt):
    SIZE = 32


class Int64(SignedFixedInt):
    SIZE = 64


class UInt8(FixedInt):
    SIZE = 8


class UInt16(FixedInt):
    SIZE = 16


class UInt32(FixedInt):
    SIZE = 32


class UInt64(FixedInt):
    SIZE = 64


class UInt(Primitive, Sizable):
    SIGNED = False
    SIZABLE_CLS = FixedInt
    val: int

    def serialize(self):
        val = int_to_bytes(self.val)
        return pack_len(val) + val


    @classmethod
    def _deserialize(cls, data):
        data, val_len = unpack_len(data)
        val = int.from_bytes(data[:val_len], 'big', signed=cls.SIGNED)
        return data[val_len:], val


    def __int__(self):
        return self.val


class Int(Sizable):
    SIGNED = True
    SIZABLE_CLS = SignedFixedInt


class List(Subtypable):
    SUBTYPE = None
    val: list

    def __init__(self, val=None) -> None:
        val  = [] if val is None else val
        args = [a if type(a) is self.SUBTYPE else self.SUBTYPE(a) for a in val]
        super().__init__(args)

    def serialize(self):
        data = b''
        for v in self.val:
            data += v.serialize()
        
        return pack_len(self.val) + data


    @classmethod
    def _deserialize(cls, data):
        objs = []
        data, val_len = unpack_len(data)
        for _ in range(val_len):
            data, obj = cls.SUBTYPE.deserialize(data)
            objs.append(obj)
    
        return data, cls(objs)
    

    def native(self):
        return [elem.native() for elem in self.val]


    def __iter__(self):
        return self.val.__iter__()


    def __getitem__(self, idx):
        return self.val[idx]


    def __len__(self):
        return len(self.val)


    def __delitem__(self, idx):
        del self.val[idx]


    def append(self, item):
        if type(item) is not self.SUBTYPE:
            raise TypeError

        self.val.append(item)



class FixedBytes(Primitive, Serializable, Subscriptable):
    SIZE = None
    val: bytes

    def __init__(self, val, **kwargs) -> None:
        if len(val) > self.SIZE:
            raise OverflowError('Bytes value too large')

        super().__init__(val, **kwargs)

    def serialize(self):
        return b'\x00'*(self.SIZE-len(self.val)) + self.val

    @classmethod
    def _deserialize(cls, data):
        return data[cls.SIZE:], cls(data[:cls.SIZE])


class Bytes(Primitive, Sizable, Subscriptable):
    SIZABLE_CLS = FixedBytes
    val: bytes

    def serialize(self):
        return pack_len(self.val) + self.val

    @staticmethod
    def _deserialize(data):
        data, val_len = unpack_len(data)
        return data[val_len:], Bytes(data[:val_len])


class HungryBytes(Primitive, Serializable):
    val: bytes

    def serialize(self):
        return self.val

    @staticmethod
    def _deserialize(data):
        return b'', HungryBytes(data)



class TypedEnum(Serializable, _Enum):

    def __init__(self, val) -> None:
        pass

    def __repr__(self):
        return _Enum.__repr__(self)

    def __str__(self):
        return _Enum.__str__(self)

    def __boformat__(self, *args, **kwargs):
        return _Enum.__repr__(self)


    @property
    def val(self):
        return self.SUBTYPE(self.value)


    def serialize(self):
        return self.val.serialize()

    @classmethod
    def _deserialize(cls, data):
        left_over, i8 = cls.SUBTYPE.deserialize(data)
        return left_over, cls(i8.native())


class Enum(Subtypable):
    TYPED_CLS = TypedEnum



class FixedIntFlag(Serializable, _IntFlag):
    def __init__(self, val) -> None:
        pass

    @property
    def val(self):
        return UInt[self.SIZE](self._value_)

    def __repr__(self):
        return _IntFlag.__repr__(self)

    def __str__(self):
        return _IntFlag.__str__(self)

    def __boformat__(self, *args, **kwargs):
        return _IntFlag.__repr__(self)


    def serialize(self):
        return self.val.serialize()


    @classmethod
    def _deserialize(cls, data):
        left_over, i8 = UInt[cls.SIZE].deserialize(data)
        return left_over, cls(i8.native())


class IntFlag(Sizable):
    SIZABLE_CLS = FixedIntFlag
