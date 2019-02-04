from samson.macs.cmac import CMAC
from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael
from copy import deepcopy

def dbl(bytestring):
    if bytestring.int() & 0x80000000000000000000000000000000:
        bytestring = (bytestring << 1) ^ 0x00000000000000000000000000000087
    else:
        bytestring = bytestring << 1

    return bytestring


class S2V(object):
    """
    S2V KDF described in RFC5297 (https://tools.ietf.org/html/rfc5297)
    """

    def __init__(self, key: bytes, cipher: object=Rijndael, iv: bytes=b'\x00'*16):
        """
        Parameters:
            key    (bytes): Bytes-like object to key the underlying cipher.
            cipher (class): Instantiable class representing a block cipher.
            iv     (bytes): Initialization vector.
        """
        self.cmac = CMAC(key, cipher)
        self.iv = iv


    def __repr__(self):
        return f"<S2V: cmac={self.cmac}, iv={self.iv}>"

    def __str__(self):
        return self.__repr__()


    def derive(self, *strings: bytes) -> Bytes:
        """
        Derives a key.

        Parameters:
            *strings  (*args, bytes): Variadic args of bytestrings.
        
        Returns:
            Bytes: Derived key.
        """
        if len(strings) == 0:
            return self.cmac.generate(0x01)

        derived_iv = self.cmac.generate(self.iv)

        for bytestring in strings[:-1]:
            derived_iv = dbl(derived_iv)
            derived_iv ^= self.cmac.generate(bytestring)

        last_str = deepcopy(strings[-1])
        if len(last_str) < 16:
            derived_iv = dbl(derived_iv)
            last_str += b'\x80'
            last_str  = last_str + (b'\x00' * (16 - len(last_str)))

        derived_iv = derived_iv.zfill(len(last_str)) ^ last_str

        return self.cmac.generate(derived_iv)
