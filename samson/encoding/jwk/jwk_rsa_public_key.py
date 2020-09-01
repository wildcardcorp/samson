from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.encoding.jwk.jwk_base import JWKBase
import json

class JWKRSAPublicKey(JWKBase):
    """
    JWK encoder for RSA public keys
    """

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        """
        Checks if `buffer` can be parsed with this encoder.

        Parameters:
            buffer (bytes): Buffer to check.
        
        Returns:
            bool: Whether or not `buffer` is the correct format.
        """
        try:
            if issubclass(type(buffer), (bytes, bytearray)):
                buffer = buffer.decode()

            jwk = json.loads(buffer)
            return jwk['kty'] == 'RSA' and not ('d' in jwk)
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


    @staticmethod
    def build_pub(rsa_key: 'RSA') -> dict:
        """
        Formats the public parameters of the key as a `dict`.

        Parameters:
            rsa_key (RSA): Key to format.
        
        Returns:
            dict: JWK dict with public parameters.
        """
        jwk = {
            'kty': 'RSA',
            'n': url_b64_encode(Bytes(rsa_key.n)).decode(),
            'e': url_b64_encode(Bytes(rsa_key.e)).decode(),
        }

        return jwk



    def encode(self, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            rsa_key (RSA): RSA key to encode.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = JWKRSAPublicKey.build_pub(self.key)
        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        """
        Decodes a JWK JSON string into an RSA object.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            RSA: RSA object.
        """
        from samson.public_key.rsa import RSA

        if issubclass(type(buffer), (bytes, bytearray)):
            buffer = buffer.decode()

        jwk = json.loads(buffer)
        n = Bytes(url_b64_decode(jwk['n'].encode('utf-8'))).int()
        e = Bytes(url_b64_decode(jwk['e'].encode('utf-8'))).int()

        if 'p' in jwk:
            p = Bytes(url_b64_decode(jwk['p'].encode('utf-8'))).int()
            q = Bytes(url_b64_decode(jwk['q'].encode('utf-8'))).int()
        else:
            p = 2
            q = 3


        rsa = RSA(8, p=p, q=q, e=e)
        rsa.n = n
        rsa.bits = rsa.n.bit_length()

        return JWKRSAPublicKey(rsa)
