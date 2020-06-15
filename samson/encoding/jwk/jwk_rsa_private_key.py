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
            return jwk['kty'] == 'RSA' and 'd' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


    @staticmethod
    def encode(rsa_key: 'RSA', **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            rsa_key (RSA): RSA key to encode.
        
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
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        """
        Decodes a JWK JSON string into an RSA object.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            RSA: RSA object.
        """
        return JWKRSAPublicKey.decode(buffer)
