from samson.utilities.bytes import Bytes
from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_rsa_private_key import PKCS8RSAPrivateKey
from samson.encoding.x509.x509_rsa_subject_public_key import X509RSASubjectPublicKey
from samson.encoding.x509.x509_public_key_base import X509PublicKeyBase
from pyasn1.type.univ import ObjectIdentifier, BitString, Sequence, Null
from pyasn1.codec.der import encoder, decoder

class X509RSAPublicKey(X509PublicKeyBase):

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            return not PKCS8RSAPrivateKey.check(buffer) and len(items) == 2 and str(items[0][0]) == '1.2.840.113549.1.1.1'
        except Exception as _:
            return False


    def encode(self, **kwargs) -> bytes:
        seq = Sequence()
        seq.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        seq.setComponentByPosition(1, Null())

        param_bs = X509RSASubjectPublicKey.encode(self.key)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, seq)
        top_seq.setComponentByPosition(1, param_bs)

        encoded = encoder.encode(top_seq)
        return X509RSAPublicKey.transport_encode(encoded, **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)

        if type(items[1]) is BitString:
            if str(items[0][0]) == '1.2.840.113549.1.1.1':
                bitstring_seq = decoder.decode(Bytes(int(items[1])))[0]
                items = list(bitstring_seq)
            else:
                raise ValueError('Unable to decode RSA key.')

        n, e = [int(item) for item in items]
        rsa = RSA(n=n, e=e)
        return X509RSAPublicKey(rsa)
