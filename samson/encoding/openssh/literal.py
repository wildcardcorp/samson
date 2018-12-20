from samson.utilities.bytes import Bytes
from samson.encoding.openssh.openssh_type import OpenSSHType

class Literal(OpenSSHType):
    def __init__(self, name, length=4):
        self.name = name
        self.length = length


    def __repr__(self):
        return f"<Literal name={self.name}, length={self.length}>"

    def __str__(self):
        return self.__repr__()

    
    def pack(self, value):
        val = Bytes.wrap(value)
        if len(val) > 0:
            val = val.zfill(self.length)
        else:
            val = b''
        return val
    
    
    def unpack(self, encoded_bytes):
        return encoded_bytes[:self.length], encoded_bytes[self.length:]