from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_decode, url_b64_encode
import json

class JWKRSAPublicKey(object):
    """
    JWK encoder for RSA public keys
    """

    DEFAULT_MARKER = None
    DEFAULT_PEM = False
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer, **kwargs):
        try:
            if issubclass(type(buffer), (bytes, bytearray)):
                buffer = buffer.decode()

            jwk = json.loads(buffer)
            return jwk['kty'] == 'RSA' and not ('d' in jwk)
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


    @staticmethod
    def build_pub(rsa_key):
        jwk = {
            'kty': 'RSA',
            'n': url_b64_encode(Bytes(rsa_key.n)).decode(),
            'e': url_b64_encode(Bytes(rsa_key.e)).decode(),
        }

        return jwk


    @staticmethod
    def encode(rsa_key: object, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            rsa_key     (RSA): RSA key to encode.
            is_private (bool): Whether or not `rsa_key` is a private key and to encode private parameters.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = JWKRSAPublicKey.build_pub(rsa_key)
        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> (int, int, int, int):
        """
        Decodes a JWK JSON string into ECDSA parameters.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            (int, int, int, int): RSA parameters formatted as (n, e, p, q).
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

        return rsa
