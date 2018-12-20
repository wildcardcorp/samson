from samson.utilities.bytes import Bytes

class Specification(object):
    SPEC = None

    def __init__(self, spec):
        self.spec = spec
    

    def __repr__(self):
        return f"<Specification spec={self.spec}>"

    def __str__(self):
        return self.__repr__()


    def pack(self):
        val = Bytes(b'')
        self_dict = self.__dict__
        for item in self.spec:
            val += item.pack(self_dict[item.name])
        
        return val

    
    @classmethod
    def unpack(cls, encoded_bytes):
        encoded_bytes = Bytes.wrap(encoded_bytes)
        vals = {}
        for item in cls.SPEC:
            val, encoded_bytes = item.unpack(encoded_bytes)
            vals[item.name] = val

        return cls(**vals)