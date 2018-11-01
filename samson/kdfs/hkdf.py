import math
from samson.macs.hmac import HMAC

# https://en.wikipedia.org/wiki/HKDF
# https://tools.ietf.org/html/rfc5869
class HKDF(object):
    def __init__(self, hash_obj, desired_len):
        self.hash_obj = hash_obj
        self.desired_len = desired_len


    def __repr__(self):
        return f"<HKDF: hash_obj={self.hash_obj}, desired_len={self.desired_len}>"


    def __str__(self):
        return self.__repr__()

    
    def derive(self, key, salt, info=b''):
        prk = HMAC(key=salt, hash_obj=self.hash_obj).generate(key)
        hmac = HMAC(key=prk, hash_obj=self.hash_obj)

        new_key = b''
        t = b''
        for i in range(math.ceil(self.desired_len / (self.hash_obj.digest_size // 8))):
            t = hmac.generate(t + info + bytes([i + 1]))
            new_key += t

        return new_key[:self.desired_len]