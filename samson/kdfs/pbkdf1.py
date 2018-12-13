from samson.utilities.bytes import Bytes
from types import FunctionType

class PBKDF1(object):
    """
    Password-based Key Derivation Function v1.
    """

    def __init__(self, hash_fn: FunctionType, desired_len: int, num_iters: int):
        """
        Parameters:
            hash_fn    (func): Function that takes in bytes and returns them hashed.
            desired_len (int): Desired output length.
            num_iters   (int): Number of iterations to perform.
        """
        self.hash_fn = hash_fn
        self.num_iters = num_iters
        self.desired_len = desired_len


    def __repr__(self):
        return f"<PBKDF1: hash_fn={self.hash_fn}, desired_len={self.desired_len} num_iters={self.num_iters}>"

    def __str__(self):
        return self.__repr__()


    def derive(self, password: bytes, salt: bytes) -> Bytes:
        """
        Derives a key.

        Parameters:
            password (bytes): Bytes-like object to key the internal state.
            salt     (bytes): Salt to tweak the output.
        
        Returns:
            Bytes: Derived key.
        """
        last_result = password + salt
        for _ in range(self.num_iters):
            last_result = self.hash_fn(last_result)

        return last_result[:self.desired_len]
