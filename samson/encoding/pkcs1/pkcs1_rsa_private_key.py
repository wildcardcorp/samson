from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pem import PEMEncodable

class PKCS1RSAPrivateKey(PEMEncodable):
    DEFAULT_MARKER = 'RSA PRIVATE KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 9 and int(items[0]) == 0
        except Exception as _:
            return False


    @staticmethod
    def encode(rsa_key: object, **kwargs):
        encoded = export_der([0, rsa_key.n, rsa_key.e, rsa_key.alt_d, rsa_key.p, rsa_key.q, rsa_key.dP, rsa_key.dQ, rsa_key.Qi])
        encoded = PKCS1RSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)

        items = [int(item) for item in items]
        del items[6:]
        del items[0]

        _n, e, _d, p, q = items

        rsa = RSA(0, p=p, q=q, e=e)
        rsa.bits = rsa.n.bit_length()

        return rsa
