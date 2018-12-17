from samson.utilities.bytes import Bytes

class DGHVBit(int):
    """
    Convenience class for DGHV bit operations.
    """

    def __new__(cls, val, *args, **kwargs):
        return super(DGHVBit, cls).__new__(cls, val)

    def NOT(self):
        return DGHVBit(1 + self)


    def AND(self, b: int):
        return DGHVBit(self * b)


    def NAND(self, b: int):
        return DGHVBit(self.AND(b).NOT())


    def OR(self, b: int):
        return self.NAND(self).NAND(b.NAND(b))


    def XOR(self, b: int):
        return DGHVBit(self.NOT() * b + b.NOT() * self)


    def __invert__(self):
        return self.NOT()


    def __or__(self, b: int):
        return self.OR(b)


    def __and__(self, b: int):
        return self.AND(b)


    def __xor__(self, b: int):
        return self.XOR(b)



class DGHV(object):
    """
    The Dijk-Gentry-Halevi-Vaikuntanathan (DGHV) fully-homomorphic encryption scheme
    """

    def __init__(self, p: int=None):
        """
        Parameters:
            p (int): Key.
        """
        self.p = p or Bytes.random(8).to_int()


    def __repr__(self):
        return f"<DGHV: p={self.p}>"

    def __str__(self):
        return self.__repr__()



    def encrypt(self, m: int) -> DGHVBit:
        """
        Encrypts a bit `m`.

        Parameters:
            m (int): Number to encrypt.

        Returns:
            DGHVBit: Encrypted bit.
        """
        q = Bytes.random(8).to_int()
        r = Bytes.random(8).to_int() % (self.p // 4)
        return DGHVBit(self.p * q + 2 * r + m)



    def decrypt(self, c: int) -> int:
        """
        Decrypts a number `c` into a plaintext bit.

        Parameters:
            c (int): Encrypted int or DGHVBit.
        
        Returns:
            int: Plaintext bit.
        """
        return (c % self.p) % 2
