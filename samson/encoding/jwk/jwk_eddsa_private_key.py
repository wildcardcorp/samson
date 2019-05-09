from samson.encoding.general import url_b64_encode
from samson.encoding.jwk.jwk_eddsa_public_key import JWKEdDSAPublicKey
import json

class JWKEdDSAPrivateKey(object):
    """
    JWK encoder for EdDSA private keys
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
            return jwk['kty'] == 'OKP' and jwk['crv'] in ['Ed25519', 'Ed448', 'X25519', 'X448'] and 'd' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


    @staticmethod
    def encode(eddsa_key: object, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            eddsa_key (EdDSA): EdDSA key to encode.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = JWKEdDSAPublicKey.build_pub(eddsa_key)
        jwk['d'] = url_b64_encode(eddsa_key.d).decode()

        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> object:
        """
        Decodes a JWK JSON string into an EdDSA object.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            EdDSA: EdDSA object.
        """
        return JWKEdDSAPublicKey.decode(buffer)
