from samson.utilities.bytes import Bytes

class RC4(object):
    def __init__(self, key):
        self.key = key
        self.S = self.key_schedule(key)
        self.i = 0
        self.j = 0


    def __repr__(self):
        return "<RC4: key={}, S={}, i={}, j={} >".format(self.key, self.S, self.i, self.j)

    def __str__(self):
        return self.__repr__()


    def key_schedule(self, key):
        key_length = len(key)
        S = []
        for i in range(256):
            S.append(i)

        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % key_length]) % 256
            S[i], S[j] = S[j], S[i]
        
        return S


    def yield_state(self, length):
        keystream = Bytes(b'')
        
        for _ in range(length):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            keystream += bytes([self.S[(self.S[self.i] + self.S[self.j]) % 256]])

        return keystream