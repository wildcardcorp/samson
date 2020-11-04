from samson.utilities.bytes import Bytes
from samson.core.primitives import KDF, Primitive
from samson.ace.decorators import register_primitive
from types import FunctionType
from math import ceil

@register_primitive()
class PBKDF2(KDF):
    def __init__(self, hash_fn: FunctionType, desired_len: int, num_iters: int):
        """
        Parameters:
            hash_fn    (func): Function that takes in a key and input bytes and returns them hashed.
            desired_len (int): Desired output length.
            num_iters   (int): Number of iterations to perform.
        """
        self.hash_fn     = hash_fn
        self.desired_len = desired_len
        self.num_iters   = num_iters
        Primitive.__init__(self)



    def __reprdir__(self):
        return ['hash_fn', 'desired_len', 'num_iters']


    def derive(self, password: bytes, salt: bytes) -> Bytes:
        """
        Derives a key.

        Parameters:
            password (bytes): Bytes-like object to key the internal state.
            salt     (bytes): Salt to tweak the output.

        Returns:
            Bytes: Derived key.
        """
        hash_len   = len(self.hash_fn(b'', b''))
        num_blocks = ceil(self.desired_len / hash_len)

        output = Bytes(b'')
        for i in range(1, num_blocks + 1):
            xor_sum = Bytes(b'').zfill(hash_len)
            last    = salt + Bytes(i).zfill(4)

            for _ in range(self.num_iters):
                last     = self.hash_fn(password, last)
                xor_sum ^= last

            output += xor_sum

        return output[:self.desired_len]
