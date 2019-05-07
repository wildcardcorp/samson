from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_decode, url_b64_encode
import json

class JWKOctKey(object):
    """
    JWK encoder for octect keys
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
            return jwk['kty'] == 'oct' and 'k' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


    @staticmethod
    def encode(key: bytes, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            key (bytes): Key to encode.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = {
            'kty': 'oct',
            'k': url_b64_encode(key).decode()
        }
        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> Bytes:
        """
        Decodes a JWK JSON string into a key.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            Bytes: Key.
        """
        if issubclass(type(buffer), (bytes, bytearray)):
            buffer = buffer.decode()

        jwk = json.loads(buffer)
        return Bytes(url_b64_decode(jwk['k'].encode()))
