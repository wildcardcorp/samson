class PBKDF1(object):
    def __init__(self, hash_fn, desired_len, num_iters):
        self.hash_fn = hash_fn
        self.num_iters = num_iters
        self.desired_len = desired_len


    def __repr__(self):
        return f"<PBKDF1: hash_fn={self.hash_fn}, desired_len={self.desired_len} num_iters={self.num_iters}>"

    def __str__(self):
        return self.__repr__()


    def derive(self, password, salt):
        last_result = password + salt
        for _ in range(self.num_iters):
            last_result = self.hash_fn(last_result)
        
        return last_result[:self.desired_len]