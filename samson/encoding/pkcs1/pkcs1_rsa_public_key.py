from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pem import PEMEncodable

class PKCS1RSAPublicKey(PEMEncodable):
    DEFAULT_MARKER = 'RSA PUBLIC KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 2
        except Exception as _:
            return False


    @staticmethod
    def encode(rsa_key: object, **kwargs):
        encoded = export_der([rsa_key.n, rsa_key.e])
        encoded = PKCS1RSAPublicKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)
        items = [int(item) for item in items]

        n, e = items

        rsa = RSA(8, e=e)
        rsa.n = n
        rsa.bits = rsa.n.bit_length()

        return rsa
