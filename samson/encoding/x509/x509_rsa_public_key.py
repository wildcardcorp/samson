from samson.utilities.bytes import Bytes
from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_rsa_private_key import PKCS8RSAPrivateKey
from samson.encoding.x509.x509_rsa_subject_public_key import X509RSASubjectPublicKey
from pyasn1.type.univ import ObjectIdentifier, BitString, Sequence, Null
from pyasn1.codec.der import encoder, decoder

class X509RSAPublicKey(object):

    @staticmethod
    def check(buffer: bytes):
        try:
            items = bytes_to_der_sequence(buffer)
            return not PKCS8RSAPrivateKey.check(buffer) and len(items) == 2 and str(items[0][0]) == '1.2.840.113549.1.1.1'
        except Exception as _:
            return False


    @staticmethod
    def encode(rsa_key: object):
        seq = Sequence()
        seq.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        seq.setComponentByPosition(1, Null())

        param_bs = X509RSASubjectPublicKey.encode(rsa_key)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, seq)
        top_seq.setComponentByPosition(1, param_bs)

        encoded = encoder.encode(top_seq)
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)

        if type(items[1]) is BitString:
            if str(items[0][0]) == '1.2.840.113549.1.1.1':
                bitstring_seq = decoder.decode(Bytes(int(items[1])))[0]
                items = list(bitstring_seq)
            else:
                raise ValueError('Unable to decode RSA key.')

        n, e = [int(item) for item in items]
        rsa = RSA(8, e=e)
        rsa.n = n

        rsa.bits = rsa.n.bit_length()

        return rsa
