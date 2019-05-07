from samson.utilities.bytes import Bytes
from samson.utilities.ecc import EdwardsCurve25519, EdwardsCurve448
from samson.encoding.general import url_b64_decode, url_b64_encode
import json

JWK_CURVE_NAME_LOOKUP = {
    EdwardsCurve25519: 'Ed25519',
    EdwardsCurve448: 'Ed448'
}

JWK_INVERSE_CURVE_LOOKUP = {v:k for k, v in JWK_CURVE_NAME_LOOKUP.items()}

class JWKEdDSAPublicKey(object):
    """
    JWK encoder for EdDSA public keys
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
            return jwk['kty'] == 'OKP' and jwk['crv'] in ['Ed25519', 'Ed448'] and not 'd' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False



    @staticmethod
    def build_pub(eddsa_key: object) -> dict:
        """
        Formats the public parameters of the key as a `dict`.

        Parameters:
            eddsa_key (EdDSA): Key to format.
        
        Returns:
            dict: JWK dict with public parameters.
        """
        jwk = {
            'kty': 'OKP',
            'crv': JWK_CURVE_NAME_LOOKUP[eddsa_key.curve],
            'x': url_b64_encode(eddsa_key.encode_point(eddsa_key.A)).decode()
        }

        return jwk


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
        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> object:
        """
        Decodes a JWK JSON string into EdDSA parameters.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            (Curve, int, int, int): EdDSA parameters formatted as (curve, x, y, d).
        """
        from samson.public_key.eddsa import EdDSA

        if issubclass(type(buffer), (bytes, bytearray)):
            buffer = buffer.decode()

        jwk = json.loads(buffer)

        curve = JWK_INVERSE_CURVE_LOOKUP[jwk['crv']]
        x = Bytes(url_b64_decode(jwk['x'].encode('utf-8')))

        if 'd' in jwk:
            d = Bytes(url_b64_decode(jwk['d'].encode('utf-8'))).int()
        else:
            d = 0


        eddsa   = EdDSA(curve=curve, d=d)
        eddsa.A = eddsa.decode_point(x)
        return eddsa
