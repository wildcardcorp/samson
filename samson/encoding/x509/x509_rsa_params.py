from samson.utilities.bytes import Bytes
from samson.encoding.general import bytes_to_der_sequence
from pyasn1.type.univ import Integer, ObjectIdentifier, BitString, SequenceOf, Sequence, Null
from pyasn1.codec.der import encoder, decoder
import math

class X509RSAParams(object):

    @staticmethod
    def encode(rsa_key: object):
        param_seq = SequenceOf()
        param_seq.append(Integer(rsa_key.n))
        param_seq.append(Integer(rsa_key.e))

        param_bs = bin(Bytes(encoder.encode(param_seq)).int())[2:]
        param_bs = param_bs.zfill(math.ceil(len(param_bs) / 8) * 8)
        param_bs = BitString(param_bs)

        return param_bs


    @staticmethod
    def decode(buffer: bytes):
        pass