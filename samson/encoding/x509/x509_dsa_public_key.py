from samson.utilities.bytes import Bytes
from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_dsa_private_key import PKCS8DSAPrivateKey
from pyasn1.type.univ import Integer, ObjectIdentifier, BitString, SequenceOf, Sequence
from pyasn1.codec.der import encoder, decoder
import math

class X509DSAPublicKey(object):

    @staticmethod
    def check(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return not PKCS8DSAPrivateKey.check(buffer) and len(items) == 2 and str(items[0][0]) == '1.2.840.10040.4.1'


    @staticmethod
    def encode(dsa_key: object):
        seq_of = SequenceOf()
        seq_of.extend([Integer(dsa_key.p), Integer(dsa_key.q), Integer(dsa_key.g)])

        seq = Sequence()
        seq.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 10040, 4, 1]))
        seq.setComponentByPosition(1, seq_of)

        y_bits = bin(Bytes(encoder.encode(Integer(dsa_key.y))).int())[2:]
        y_bits = y_bits.zfill(math.ceil(len(y_bits) / 8) * 8)
        y_bits = BitString(y_bits)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, seq)
        top_seq.setComponentByPosition(1, y_bits)

        encoded = encoder.encode(top_seq)
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.dsa import DSA
        items = bytes_to_der_sequence(buffer)

        y_sequence_bytes = Bytes(int(items[1]))
        y = int(decoder.decode(y_sequence_bytes)[0])
        p, q, g = [int(item) for item in items[0][1]]

        dsa = DSA(None, p=p, q=q, g=g, x=0)
        dsa.y = y

        return dsa
