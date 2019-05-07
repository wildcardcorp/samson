from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_encode
from samson.encoding.jwk.jwk_ec_public_key import JWKECPublicKey
import json

class JWKECPrivateKey(object):
    """
    JWK encoder for ECDSA private keys
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
            return jwk['kty'] == 'EC' and 'd' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


    @staticmethod
    def encode(ec_key: object, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            ec_key (ECDSA): ECDSA key to encode.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = JWKECPublicKey.build_pub(ec_key)
        jwk['d'] = url_b64_encode(Bytes(ec_key.d)).decode()

        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> object:
        """
        Decodes a JWK JSON string into an ECDSA object.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            ECDSA: ECDSA object.
        """
        return JWKECPublicKey.decode(buffer)
