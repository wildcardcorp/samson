from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pkcs1.pkcs1_rsa_private_key import PKCS1RSAPrivateKey
from pyasn1.type.univ import Integer, ObjectIdentifier, BitString, SequenceOf, Sequence, Null

class PKCS8RSAPrivateKey(object):
    @staticmethod
    def check(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return len(items) == 3 and str(cert[1][0]) == '1.2.840.113549.1.1.1'

    @staticmethod
    def encode(rsa_key: object):
        encoded = PKCS1RSAPrivateKey.encode(rsa_key)
        top_seq = Sequence()
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)

        items = [int(item) for item in items]
        del items[6:]
        del items[0]

        _n, e, _d, p, q = items

        rsa = RSA(0, p=p, q=q, e=e)
        rsa.bits = rsa.n.bit_length()

        return rsa
