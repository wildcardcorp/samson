from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Integer, BitString
from pyasn1.codec.der import encoder
import math

class X509DSASubjectPublicKey(object):

    @staticmethod
    def encode(dsa_key: 'DSA') -> BitString:
        y_bits = bin(Bytes(encoder.encode(Integer(dsa_key.y))).int())[2:]
        y_bits = y_bits.zfill(math.ceil(len(y_bits) / 8) * 8)
        y_bits = BitString(y_bits)

        return y_bits


    @staticmethod
    def decode(buffer: bytes) -> 'DSA':
        pass
