from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pem import PEMEncodable

class PKCS1DSAPrivateKey(PEMEncodable):
    """
    Not in the RFC spec, but OpenSSL supports it.
    """

    DEFAULT_MARKER = 'DSA PRIVATE KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes, **kwargs):
        items = bytes_to_der_sequence(buffer)
        return len(items) == 6 and int(items[0]) == 0


    @staticmethod
    def encode(dsa_key: object, **kwargs):
        encoded = export_der([0, dsa_key.p, dsa_key.q, dsa_key.g, dsa_key.y, dsa_key.x])
        encoded = PKCS1DSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.dsa import DSA
        items = bytes_to_der_sequence(buffer)

        p, q, g, y, x = [int(item) for item in items[1:6]]
        dsa = DSA(None, p=p, q=q, g=g, x=x)
        dsa.y = y

        return dsa
