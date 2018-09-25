from samson.utilities.bytes import Bytes
from samson.utilities.padding import pkcs7_pad

class FeistelNetwork(object):
    def __init__(self, round_func, key_schedule):
        self.round_func = round_func
        self.key_schedule = key_schedule


    def yield_encrypt(self, key, plaintext):
        half = len(plaintext) // 2
        plaintext = Bytes.wrap(plaintext)
        L_i, R_i = plaintext[:half], plaintext[half:]
        
        round_keys = list(self.key_schedule(key))

        for subkey in round_keys:
            L_i, R_i = R_i, (L_i ^ self.round_func(R_i, subkey))
            yield R_i, L_i



    def yield_decrypt(self, key, ciphertext):
        half = len(ciphertext) // 2
        ciphertext = Bytes.wrap(ciphertext)
        R_i, L_i = ciphertext[:half], ciphertext[half:]

        round_keys = list(self.key_schedule(key))[::-1]

        for subkey in round_keys:
            R_i, L_i = L_i, (R_i ^ self.round_func(L_i, subkey))
            yield L_i, R_i



    def encrypt(self, key, plaintext):
        return Bytes(b''.join(list(self.yield_encrypt(key, plaintext))[-1]))

    
    def decrypt(self, key, ciphertext):
        return Bytes(b''.join(list(self.yield_decrypt(key, ciphertext))[-1]))