from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Integer, BitString
from pyasn1.codec.der import encoder
import math

class X509DiffieHellmanSubjectPublicKey(object):

    @staticmethod
    def encode(dh_key: 'DiffieHellman') -> BitString:
        pub_bs = bin(Bytes(encoder.encode(Integer(dh_key.get_challenge()))).int())[2:]
        pub_bs = pub_bs.zfill(math.ceil(len(pub_bs) / 8) * 8)
        pub_bs = BitString(pub_bs)

        return pub_bs


    @staticmethod
    def decode(buffer: bytes) -> 'DiffieHellman':
        pass
