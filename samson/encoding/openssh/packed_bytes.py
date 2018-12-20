from samson.utilities.bytes import Bytes
from samson.encoding.openssh.openssh_type import OpenSSHType
import math

class PackedBytes(OpenSSHType):
    def __init__(self, name):
        self.name = name
    

    def __repr__(self):
        return f"<PackedBytes name={self.name}>"

    def __str__(self):
        return self.__repr__()

    
    def pack(self, value, force_pack=False):
        val = value
        if issubclass(type(value), OpenSSHType):
            val = value.pack()

        val = Bytes.wrap(val)

        if issubclass(type(value), int):
            val = val.zfill(math.ceil((value.bit_length() + 1) / 8))
        
        if len(val) > 0 or force_pack:
            length = Bytes(len(val)).zfill(4)
        else:
            length = b''

        return length  + val
    

    def unpack(self, encoded_bytes):
        length = encoded_bytes[:4].int()
        return encoded_bytes[4:length + 4], encoded_bytes[length + 4:]