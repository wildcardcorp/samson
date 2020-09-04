from samson.macs.cmac import CMAC
from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael
from samson.core.primitives import EncryptionAlg, KDF, Primitive
from samson.core.metadata import SizeType, SizeSpec
from samson.ace.decorators import register_primitive
from copy import deepcopy

def dbl(bytestring):
    if bytestring.int() & 0x80000000000000000000000000000000:
        bytestring = (bytestring << 1) ^ 0x00000000000000000000000000000087
    else:
        bytestring = bytestring << 1

    return bytestring


@register_primitive()
class S2V(KDF):
    """
    S2V KDF described in RFC5297 (https://tools.ietf.org/html/rfc5297)
    """

    BLOCK_SIZE = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda s2v: s2v.cipher.BLOCK_SIZE)

    def __init__(self, cipher: EncryptionAlg=None, iv: bytes=b'\x00'*16):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Initialization vector.
        """
        self.cmac = CMAC(cipher or Rijndael(Bytes.random(32)))
        self.iv   = iv
        Primitive.__init__(self)


    def __reprdir__(self):
        return ['cmac', 'iv']


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
