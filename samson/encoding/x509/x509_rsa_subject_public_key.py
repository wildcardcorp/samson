from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Integer, BitString, SequenceOf
from pyasn1.codec.der import encoder
import math

class X509RSASubjectPublicKey(object):

    @staticmethod
    def encode(rsa_key: 'RSA') -> BitString:
        param_seq = SequenceOf()
        param_seq.append(Integer(rsa_key.n))
        param_seq.append(Integer(rsa_key.e))

        param_bs = bin(Bytes(encoder.encode(param_seq)).int())[2:]
        param_bs = param_bs.zfill(math.ceil(len(param_bs) / 8) * 8)
        param_bs = BitString(param_bs)

        return param_bs


    @staticmethod
    def decode(buffer: bytes) -> 'RSA':
        pass
