from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes

class Poly1305(object):
    P1305 = (1 << 130) - 5
    
    def __init__(self, key, nonce, r, cipher=Rijndael):
        self.key = key
        self.nonce = nonce
        self.r = Bytes.wrap(r, byteorder='little').to_int()
        self.cipher = cipher


    def __repr__(self):
        return f"<Poly1305: key={self.key}, nonce={self.nonce}, r={self.r}, cipher={self.cipher}>"


    def __str__(self):
        return self.__repr__()

    
    def generate(self, plaintext):
        pt_chunks = [(chunk + b'\x01').zfill(17) for chunk in Bytes.wrap(plaintext, byteorder='little').chunk(16, allow_partials=True)]

        total = 0
        for chunk in pt_chunks:
            total += chunk.to_int()
            total *= self.r
        
        total %= Poly1305.P1305
        enc = self.cipher(self.key).encrypt(self.nonce)
        enc.byteorder = 'little'

        return Bytes((enc.to_int() + total) % (1 << 128), byteorder='little')