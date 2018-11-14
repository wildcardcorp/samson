from samson.utilities.bytes import Bytes

class EvenMansourScheme(object):
    def __init__(self, F, K1, K2=None):
        self.F = F
        self.K1 = Bytes.wrap(K1)
        self.K2 = Bytes.wrap(K2 or K1)
        self.block_size = len(self.K1)


    def __repr__(self):
        return f"<EvenMansourScheme F={self.F}, K1={self.K1}, K2={self.K2}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()
    


    def encrypt(self, plaintext):
        k1_p = self.K1 ^ plaintext
        f_p = self.F(k1_p)
        return f_p ^ self.K2



    def decrypt(self, plaintext):
        k2_p = self.K2 ^ plaintext
        f_p = self.F(k2_p)
        return f_p ^ self.K1