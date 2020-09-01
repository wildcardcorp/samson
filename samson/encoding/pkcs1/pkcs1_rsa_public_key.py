from samson.encoding.general import export_der, bytes_to_der_sequence
from samson.encoding.pem import PEMEncodable
from samson.math.general import is_prime

class PKCS1RSAPublicKey(PEMEncodable):
    DEFAULT_MARKER = 'RSA PUBLIC KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            poss_p = int(items[0])
            return len(items) == 2 and not is_prime(poss_p)
        except Exception as _:
            return False



    def encode(self, **kwargs) -> bytes:
        encoded = export_der([self.key.n, self.key.e])
        encoded = PKCS1RSAPublicKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)
        items = [int(item) for item in items]

        n, e = items

        rsa = RSA(n=n, e=e)
        return PKCS1RSAPublicKey(rsa)
