from samson.block_ciphers.des import DES
from samson.utilities.bytes import Bytes

class TDES(object):
    def __init__(self, key):
        key = Bytes.wrap(key)
        if not len(key) in [56, 112, 168]:
            raise ValueError('`key` must be a multiple of 56')

        self.key = key
        self.des_arr = [DES(subkey) for subkey in key.chunk(56)]

    
    def __repr__(self):
        return f"<TDES: key={self.key}, des_arr={self.des_arr}>"

    def __str__(self):
        return self.__repr__()

    
    def encrypt(self, plaintext):
        plaintext = Bytes.wrap(plaintext)
        pt_1 = self.des_arr[0].encrypt(plaintext)
        pt_2 = self.des_arr[1].decrypt(pt_1)
        ciphertext = self.des_arr[2].encrypt(pt_2)

        return ciphertext


    def decrypt(self, ciphertext):
        ciphertext = Bytes.wrap(ciphertext)
        ct_1 = self.des_arr[2].decrypt(ciphertext)
        ct_2 = self.des_arr[1].encrypt(ct_1)
        plaintext = self.des_arr[0].decrypt(ct_2)

        return plaintext