import math
from samson.macs.hmac import HMAC
from samson.utilities.bytes import Bytes

# https://en.wikipedia.org/wiki/HKDF
# https://tools.ietf.org/html/rfc5869
class HKDF(object):
    """
    Key derivation function based on HMAC. Formally described in RFC5869 (https://tools.ietf.org/html/rfc5869).
    """

    def __init__(self, hash_obj: object, desired_len: int):
        """
        Parameters:
            hash_obj (object): Instantiated object with compatible hash interface.
            desired_len (int): Desired output length (in bytes).
        """
        self.hash_obj = hash_obj
        self.desired_len = desired_len


    def __repr__(self):
        return f"<HKDF: hash_obj={self.hash_obj}, desired_len={self.desired_len}>"

    def __str__(self):
        return self.__repr__()


    def derive(self, key: bytes, salt: bytes, info: bytes=b'') -> Bytes:
        """
        Derives a key.

        Parameters:
            key  (bytes): Bytes-like object to key the internal HMAC.
            salt (bytes): Salt to tweak the output.
            info (bytes): Additional data to use as tweak.
        
        Returns:
            Bytes: Derived key.
        """
        prk = HMAC(key=salt, hash_obj=self.hash_obj).generate(key)
        hmac = HMAC(key=prk, hash_obj=self.hash_obj)

        new_key = b''
        t = b''
        for i in range(math.ceil(self.desired_len / (self.hash_obj.digest_size // 8))):
            t = hmac.generate(t + info + bytes([i + 1]))
            new_key += t

        return new_key[:self.desired_len]
