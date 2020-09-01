from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import EdwardsCurve25519, EdwardsCurve448, Curve25519, Curve448
from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.encoding.jwk.jwk_base import JWKBase
import json

JWK_CURVE_NAME_LOOKUP = {
    EdwardsCurve25519: 'Ed25519',
    EdwardsCurve448: 'Ed448',
    Curve25519: 'X25519',
    Curve448: 'X448'
}

JWK_INVERSE_CURVE_LOOKUP = {v:k for k, v in JWK_CURVE_NAME_LOOKUP.items()}

class JWKEdDSAPublicKey(JWKBase):
    """
    JWK encoder for EdDSA public keys
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
            return jwk['kty'] == 'OKP' and jwk['crv'] in ['Ed25519', 'Ed448', 'X25519', 'X448'] and not 'd' in jwk
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False



    @staticmethod
    def build_pub(eddsa_key: 'EdDSA') -> dict:
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
            'x': url_b64_encode(eddsa_key.get_pub_bytes()).decode()
        }

        return jwk


    def encode(self, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            eddsa_key (EdDSA): EdDSA key to encode.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = JWKEdDSAPublicKey.build_pub(self.key)
        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'EdDSA':
        """
        Decodes a JWK JSON string into EdDSA parameters.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            EdDSA: EdDSA object.
        """
        from samson.public_key.eddsa import EdDSA
        from samson.protocols.dh25519 import DH25519

        if issubclass(type(buffer), (bytes, bytearray)):
            buffer = buffer.decode()

        jwk   = json.loads(buffer)

        curve = JWK_INVERSE_CURVE_LOOKUP[jwk['crv']]
        x     = Bytes(url_b64_decode(jwk['x'].encode('utf-8')), 'little')

        if 'd' in jwk:
            d = Bytes(url_b64_decode(jwk['d'].encode('utf-8'))).int()
        else:
            d = 0


        if jwk['crv'] in ['Ed25519', 'Ed448']:
            eddsa   = EdDSA(curve=curve, d=d)
            eddsa.A = eddsa.decode_point(x)
        else:
            eddsa   = DH25519(curve=curve, d=d, pub=x.int())

        return JWKEdDSAPublicKey(eddsa)
