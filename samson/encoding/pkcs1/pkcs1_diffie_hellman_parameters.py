from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pem import PEMEncodable
from samson.math.general import is_prime

class PKCS1DiffieHellmanParameters(PEMEncodable):
    """
    Based on OpenSSL's output.
    """

    DEFAULT_MARKER = 'DH PARAMETERS'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        items = bytes_to_der_sequence(buffer)
        try:
            poss_p = int(items[0])
            return len(items) == 2 and poss_p and is_prime(poss_p)
        except:
            return False


    @staticmethod
    def encode(dh_key: 'DiffieHellman', **kwargs) -> bytes:
        encoded = export_der([dh_key.p, dh_key.g])
        encoded = PKCS1DiffieHellmanParameters.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'DiffieHellman':
        from samson.protocols.diffie_hellman import DiffieHellman
        items = bytes_to_der_sequence(buffer)

        p, g = [int(item) for item in items]
        return DiffieHellman(g=g, p=p)
