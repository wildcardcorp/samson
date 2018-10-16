from math import ceil
from samson.utilities.bytes import Bytes

class PBKDF2(object):
    def __init__(self, hash_fn, desired_len, num_iters):
        self.hash_fn = hash_fn
        self.desired_len = desired_len
        self.num_iters = num_iters


    def derive(self, password, salt):
        hash_len = len(self.hash_fn(b'', b''))
        num_blocks = ceil(self.desired_len / hash_len)

        output = Bytes(b'')
        for i in range(1, num_blocks + 1):
            xor_sum = Bytes(b'').zfill(hash_len)
            last = salt + Bytes(i).zfill(4)

            for _ in range(self.num_iters):
                last = self.hash_fn(password, last)
                xor_sum ^= last
            
            output += xor_sum
        
        return output[:self.desired_len]