from samson.block_ciphers.modes.cbc import CBC

class CBCMAC(object):
    def __init__(self, key, cipher, iv=b'\x00' * 16):
        self.key = key
        self.iv = iv
        self.cipher = cipher

    
    def __repr__(self):
        return f"<CBCMAC: key={self.key}, iv={self.iv}, cipher={self.cipher}>"


    def __str__(self):
        return self.__repr__()

    
    def generate(self, plaintext, pad=True):
        cryptor = self.cipher(self.key)
        cbc = CBC(cryptor.encrypt, cryptor.decrypt, self.iv, cryptor.block_size // 8)
        return cbc.encrypt(plaintext, pad)[-(cryptor.block_size // 8):]