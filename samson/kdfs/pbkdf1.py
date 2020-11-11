from samson.utilities.bytes import Bytes
from samson.core.primitives import KDF, Primitive
from samson.ace.decorators import register_primitive

@register_primitive()
class PBKDF1(KDF):
    """
    Password-based Key Derivation Function v1.
    """

    def __init__(self, hash_obj: 'Hash', desired_len: int, num_iters: int):
        """
        Parameters:
            hash_obj   (Hash): Instantiated object with compatible hash interface.
            desired_len (int): Desired output length.
            num_iters   (int): Number of iterations to perform.
        """
        self.hash_obj    = hash_obj
        self.num_iters   = num_iters
        self.desired_len = desired_len
        Primitive.__init__(self)


    def __reprdir__(self):
        return ['hash_obj', 'desired_len', 'num_iters']


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
            last_result = self.hash_obj.hash(last_result)

        return last_result[:self.desired_len]
