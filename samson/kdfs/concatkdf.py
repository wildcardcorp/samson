from samson.utilities.bytes import Bytes


class ConcatKDF(object):
    """
    One-step key derivation function

    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf
    """

    def __init__(self, hash_obj: object, desired_len: int):
        """
        Parameters:
            hash_obj (object): Instantiated object with compatible hash interface.
            desired_len (int): Desired output length (in bytes).
        """
        self.hash_obj    = hash_obj
        self.desired_len = desired_len


    def __repr__(self):
        return f"<ConcatKDF: hash_obj={self.hash_obj}, desired_len={self.desired_len}>"

    def __str__(self):
        return self.__repr__()


    def derive(self, key: bytes, other_info: bytes=b'') -> Bytes:
        """
        Derives a key.

        Parameters:
            key        (bytes): Bytes-like object.
            other_info (bytes): Additional data to use as tweak.
        
        Returns:
            Bytes: Derived key.
        """
        ctr     = 1
        output  = b''
        while self.desired_len > len(output):
            output += self.hash_obj.hash(Bytes(ctr).zfill(4) + key + other_info)
            ctr    += 1

        return output[:self.desired_len]
