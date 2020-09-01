from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PKCS1ECDSAPrivateKey, parse_ec_params
from samson.encoding.x509.x509_ecdsa_params import X509ECDSAParams
from samson.encoding.x509.x509_public_key_base import X509PublicKeyBase
from samson.encoding.x509.x509_ecdsa_subject_public_key import X509ECDSASubjectPublicKey
from pyasn1.type.univ import ObjectIdentifier, SequenceOf, Sequence
from pyasn1.codec.der import encoder

class X509ECDSAPublicKey(X509PublicKeyBase):

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            return not PKCS1ECDSAPrivateKey.check(buffer) and len(items) == 2 and str(items[0][0]) == '1.2.840.10045.2.1'
        except Exception as _:
            return False



    def encode(self, **kwargs) -> bytes:
        curve_seq = [
            ObjectIdentifier([1, 2, 840, 10045, 2, 1]),
            X509ECDSAParams.encode(self.key)
        ]

        encoded = SequenceOf()
        encoded.extend(curve_seq)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, encoded)
        top_seq.setComponentByPosition(1, X509ECDSASubjectPublicKey.encode(self.key))

        encoded = encoder.encode(top_seq)
        return X509ECDSAPublicKey.transport_encode(encoded, **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        items = bytes_to_der_sequence(buffer)

        # Move up OID for convenience
        items[0] = items[0][1]
        d = 1

        x, y, curve = parse_ec_params(items, 0, 1)
        ecdsa   = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = curve(x, y)

        return X509ECDSAPublicKey(ecdsa)
