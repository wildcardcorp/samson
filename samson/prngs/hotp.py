from samson.hashes.sha1 import SHA1
from samson.macs.hmac import HMAC
from samson.utilities.bytes import Bytes
from samson.auxiliary.incrementing_counter import IncrementingCounter

class HOTP(object):
    """
    HMAC-based One-Time Password (https://tools.ietf.org/html/rfc4226)
    """

    def __init__(self, key: bytes, hash_obj: object=SHA1(), digits: int=6, counter: object=IncrementingCounter(0)):
        """
        Parameters:
            key       (bytes): Shared key.
            hash_obj (object): Instantiated hash object.
            digits      (int): Number of digits to generate.
            counter     (int): Initial counter.
        """
        self.hmac = HMAC(key, hash_obj)
        self.digits = digits
        self.counter = counter


    def __repr__(self):
        return f"<HOTP: hmac={self.hmac}, digits={self.digits}, counter={self.counter}>"

    def __str__(self):
        return self.__repr__()



    def generate(self) -> str:
        """
        Generates an OTP code as string of numbers (zero padded).

        Returns:
            str: OTP code.
        """
        ctr_hash = self.hmac.generate(Bytes.wrap(self.counter.get_value()).zfill(8))
        offset = ctr_hash[-1] & 0x0F
        code = (
            (ctr_hash[offset + 0] & 0x7F) << 24 |
            (ctr_hash[offset + 1] & 0xFF) << 16 |
            (ctr_hash[offset + 2] & 0xFF) <<  8 |
            (ctr_hash[offset + 3] & 0xFF)
        )

        return str(code % (10 ** self.digits)).zfill(self.digits)
