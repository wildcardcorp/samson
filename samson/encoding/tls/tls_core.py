from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject
from enum import Enum

class Uint64(BaseObject):
    def __init__(self, value: int) -> None:
        assert value < 2**64
        self.value = value

    def __int__(self):
        return self.value

    
    def pack(self) -> Bytes:
        return Bytes(self.value).zfill(8)

    @staticmethod
    def unpack(data: bytes) -> 'Uint64':
        return Uint64(data[:8].int()), data[8:]



class VarLenByteArray(BaseObject):
    def __init__(self, value: bytes) -> None:
        self.value = value
    
    def __getitem__(self, idx):
        return self.value[idx]
    
    def __len__(self):
        return len(self.value)

    def __bytes__(self):
        return self.value

    
    def pack(self) -> Bytes:
        return Bytes(len(self.value)).zfill(2) + Bytes.wrap(self.value)

    @staticmethod
    def unpack(data: bytes) -> 'VarLenByteArray':
        array_len = data[:2].int()
        return VarLenByteArray(data[2:array_len+2]), data[array_len+2:]



def FixLenByteArray(size):
    class _FixLenByteArray(BaseObject):
        def __init__(self, value: bytes) -> None:
            assert len(value) == size
            self.value = value
        
                
        def __getitem__(self, idx):
            return self.value[idx]
        
        def __len__(self):
            return len(self.value)

        def __bytes__(self):
            return self.value

        
        def pack(self) -> Bytes:
            return Bytes.wrap(self.value)


        @staticmethod
        def unpack(data: bytes) -> '_FixLenByteArray':
            return _FixLenByteArray(data[:size]), data[size:]

    return _FixLenByteArray



class TLSEnum(Enum):
    def pack(self):
        return Bytes(self.value)

    @classmethod
    def unpack(cls, data):
        return cls(data[0]), data[1:]

