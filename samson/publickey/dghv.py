from samson.utilities.bytes import Bytes

class DGHV(object):
    def __init__(self, p=None):
        self.p = p or Bytes.random(8).to_int()


    def __repr__(self):
        return f"<DGHV: p={self.p}>"


    def __str__(self):
        return self.__repr__()



    def encrypt(self, m):
        q = Bytes.random(8).to_int()
        r = Bytes.random(8).to_int() % (self.p // 4)
        return DGHVBit(self.p * q + 2 * r + m)

    
    def decrypt(self, c):
        return (c % self.p) % 2



class DGHVBit(int):
    def __new__(cls, val, *args, **kwargs):
        return super(DGHVBit, cls).__new__(cls, val)

    def NOT(self):
        return DGHVBit(1 + self)


    def AND(self, b):
        return DGHVBit(self * b)


    def NAND(self, b):
        return DGHVBit(self.AND(b).NOT())


    def OR(self, b):
        return self.NAND(self).NAND(b.NAND(b))


    def XOR(self, b):
        return DGHVBit(self.NOT() * b + b.NOT() * self)


    def __invert__(self):
        return self.NOT()

    
    def __or__(self, b):
        return self.OR(b)


    def __and__(self, b):
        return self.AND(b)

    
    def __xor__(self, b):
        return self.XOR(b)