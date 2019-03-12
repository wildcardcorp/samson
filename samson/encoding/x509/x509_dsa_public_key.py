from samson.utilities.bytes import Bytes
from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.x509.x509_public_key_base import X509PublicKeyBase
from samson.encoding.pkcs8.pkcs8_dsa_private_key import PKCS8DSAPrivateKey
from samson.encoding.x509.x509_dsa_subject_public_key import X509DSASubjectPublicKey
from samson.encoding.x509.x509_dsa_params import X509DSAParams
from pyasn1.type.univ import ObjectIdentifier, Sequence
from pyasn1.codec.der import encoder, decoder

class X509DSAPublicKey(X509PublicKeyBase):

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            items = bytes_to_der_sequence(buffer)
            return not PKCS8DSAPrivateKey.check(buffer) and len(items) == 2 and str(items[0][0]) == '1.2.840.10040.4.1'
        except Exception as _:
            return False


    @staticmethod
    def encode(dsa_key: object, **kwargs):
        dsa_params = X509DSAParams.encode(dsa_key)

        seq = Sequence()
        seq.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 10040, 4, 1]))
        seq.setComponentByPosition(1, dsa_params)

        y_bits = X509DSASubjectPublicKey.encode(dsa_key)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, seq)
        top_seq.setComponentByPosition(1, y_bits)

        encoded = encoder.encode(top_seq)
        return X509DSAPublicKey.transport_encode(encoded, **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.dsa import DSA
        items = bytes_to_der_sequence(buffer)

        y_sequence_bytes = Bytes(int(items[1]))
        y = int(decoder.decode(y_sequence_bytes)[0])
        p, q, g = [int(item) for item in items[0][1]]

        dsa = DSA(None, p=p, q=q, g=g, x=0)
        dsa.y = y

        return dsa
