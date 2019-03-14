from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_encode
from samson.encoding.jwk.jwk_rsa_public_key import JWKRSAPublicKey
import json

class JWKRSAPrivateKey(object):
    """
    JWK encoder for RSA private keys
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
            return jwk['kty'] == 'RSA' and 'd' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


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

        jwk['d']  = url_b64_encode(Bytes(rsa_key.alt_d)).decode()
        jwk['p']  = url_b64_encode(Bytes(rsa_key.p)).decode()
        jwk['q']  = url_b64_encode(Bytes(rsa_key.q)).decode()
        jwk['dp'] = url_b64_encode(Bytes(rsa_key.dP)).decode()
        jwk['dq'] = url_b64_encode(Bytes(rsa_key.dQ)).decode()
        jwk['qi'] = url_b64_encode(Bytes(rsa_key.Qi)).decode()

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
        return JWKRSAPublicKey.decode(buffer)
