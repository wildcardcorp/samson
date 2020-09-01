from samson.utilities.bytes import Bytes
from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.x509.x509_public_key_base import X509PublicKeyBase
from samson.encoding.pkcs8.pkcs8_diffie_hellman_private_key import PKCS8DiffieHellmanPrivateKey
from samson.encoding.x509.x509_diffie_hellman_subject_public_key import X509DiffieHellmanSubjectPublicKey
from samson.encoding.x509.x509_diffie_hellman_params import X509DiffieHellmanParams
from pyasn1.type.univ import ObjectIdentifier, Sequence
from pyasn1.codec.der import encoder, decoder

class X509DiffieHellmanPublicKey(X509PublicKeyBase):

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            return not PKCS8DiffieHellmanPrivateKey.check(buffer) and len(items) == 2 and str(items[0][0]) == '1.2.840.113549.1.3.1'
        except Exception as _:
            return False



    def encode(self, **kwargs) -> bytes:
        dh_params = X509DiffieHellmanParams.encode(self.key)

        seq = Sequence()
        seq.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 113549, 1, 3, 1]))
        seq.setComponentByPosition(1, dh_params)

        y_bits = X509DiffieHellmanSubjectPublicKey.encode(self.key)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, seq)
        top_seq.setComponentByPosition(1, y_bits)

        encoded = encoder.encode(top_seq)
        return X509DiffieHellmanPublicKey.transport_encode(encoded, **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'DiffieHellman':
        from samson.protocols.diffie_hellman import DiffieHellman
        items = bytes_to_der_sequence(buffer)

        y_sequence_bytes = Bytes(int(items[1]))
        y    = int(decoder.decode(y_sequence_bytes)[0])
        p, g = [int(item) for item in items[0][1]]

        dh = DiffieHellman(p=p, g=g, y=y)
        return X509DiffieHellmanPublicKey(dh)
