from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pem import PEMEncodable

class PKCS1DiffieHellmanParameters(PEMEncodable):
    """
    Based on OpenSSL's output.
    """

    DEFAULT_MARKER = 'DH PARAMETERS'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes, **kwargs):
        items = bytes_to_der_sequence(buffer)
        return len(items) == 2 and int(items[0]) != 0


    @staticmethod
    def encode(dh_key: object, **kwargs):
        encoded = export_der([dh_key.p, dh_key.g])
        encoded = PKCS1DiffieHellmanParameters.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.protocols.diffie_hellman import DiffieHellman
        items = bytes_to_der_sequence(buffer)

        p, g = [int(item) for item in items]
        return DiffieHellman(g=g, p=p)
