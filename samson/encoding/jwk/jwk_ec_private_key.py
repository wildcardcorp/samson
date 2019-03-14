from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_encode
from samson.encoding.jwk.jwk_ec_public_key import JWKECPublicKey
from fastecdsa.curve import Curve
import json

class JWKECPrivateKey(object):
    """
    JWK encoder for ECDSA private keys
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
            return jwk['kty'] == 'EC' and 'd' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False


    @staticmethod
    def encode(ec_key: object, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            ec_key    (ECDSA): ECDSA key to encode.
            is_private (bool): Whether or not `ec_key` is a private key and to encode private parameters.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = JWKECPublicKey.build_pub(ec_key)
        jwk['d'] = url_b64_encode(Bytes(ec_key.d)).decode()

        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> (Curve, int, int, int):
        """
        Decodes a JWK JSON string into ECDSA parameters.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            (Curve, int, int, int): ECDSA parameters formatted as (curve, x, y, d).
        """
        return JWKECPublicKey.decode(buffer)
