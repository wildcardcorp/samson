# https://www.gsma.com/aboutus/wp-content/uploads/2014/12/snow3gspec.pdf
class SNOW3G(object):
    def __init__(self):
        pass
    

    def MULx(self, V, c):
        if V >> 7:
            return ((V << 1) % 256) ^ c
        else:
            return V << 1


    def MULxPOW(self, V, i, c):
        if i == 0:
            return V
        else:
            return self.MULx(self.MULxPOW(V, i - 1, c), c)