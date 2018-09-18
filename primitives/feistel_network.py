from samson.utilities.manipulation import xor_buffs
from samson.utilities.padding import pkcs7_pad

class FeistelNetwork(object):
    def __init__(self, round_func, round_key_gen):
        self.round_func = round_func
        self.round_key_gen = round_key_gen



    def yield_state(self, key, plaintext, reverse=False):
        half = len(plaintext) // 2
        if reverse:
            R_i, L_i = plaintext[:half], plaintext[half:]
        else:
            L_i, R_i = plaintext[:half], plaintext[half:]
        

        round_keys = list(self.round_key_gen(key))

        if reverse:
            round_keys = round_keys[::-1]


        for subkey in round_keys:
            L_i, R_i = R_i, xor_buffs(L_i, self.round_func(R_i, subkey))
            yield R_i, L_i


    def yield_encrypt(self, key, plaintext):
        half = len(plaintext) // 2
        L_i, R_i = plaintext[:half], plaintext[half:]
        

        round_keys = list(self.round_key_gen(key))


        for subkey in round_keys:
            L_i, R_i = R_i, xor_buffs(L_i, self.round_func(R_i, subkey))
            yield R_i, L_i



    def yield_decrypt(self, key, ciphertext):
        half = len(ciphertext) // 2
        R_i, L_i = ciphertext[:half], ciphertext[half:]
        

        round_keys = list(self.round_key_gen(key))[::-1]

        for subkey in round_keys:
            R_i, L_i = L_i, xor_buffs(R_i, self.round_func(L_i, subkey))
            yield L_i, R_i



    def encrypt(self, key, plaintext):
        return b''.join(list(self.yield_encrypt(key, plaintext))[-1])

    
    def decrypt(self, key, ciphertext):
        return b''.join(list(self.yield_decrypt(key, ciphertext))[-1])