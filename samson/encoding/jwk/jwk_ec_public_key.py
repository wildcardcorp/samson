from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.math.algebra.curves.named import P192, P224, P256, P384, P521, GOD521
from samson.encoding.jwk.jwk_base import JWKBase
import json

JWK_CURVE_NAME_LOOKUP = {
    P192: 'P-192',
    P224: 'P-224',
    P256: 'P-256',
    P384: 'P-384',
    P521: 'P-521',
    GOD521: 'P-521'
}

JWK_INVERSE_CURVE_LOOKUP = {v:k for k, v in JWK_CURVE_NAME_LOOKUP.items() if k != GOD521}

class JWKECPublicKey(JWKBase):
    """
    JWK encoder for ECDSA public keys
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
            return jwk['kty'] == 'EC' and not ('d' in jwk)
        except (json.JSONDecodeError, UnicodeDecodeError) as _:
            return False



    @staticmethod
    def build_pub(ec_key: 'ECDSA') -> dict:
        """
        Formats the public parameters of the key as a `dict`.

        Parameters:
            ec_key (ECDSA): Key to format.
        
        Returns:
            dict: JWK dict with public parameters.
        """
        jwk = {
            'kty': 'EC',
            'crv': JWK_CURVE_NAME_LOOKUP[ec_key.G.curve],
            'x': url_b64_encode(Bytes(int(ec_key.Q.x))).decode(),
            'y': url_b64_encode(Bytes(int(ec_key.Q.y))).decode(),
        }

        return jwk



    def encode(self, **kwargs) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            ec_key (ECDSA): ECDSA key to encode.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = JWKECPublicKey.build_pub(self.key)
        return json.dumps(jwk).encode('utf-8')


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        """
        Decodes a JWK JSON string into an ECDSA object.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            ECDSA: ECDSA object.
        """
        from samson.public_key.ecdsa import ECDSA

        if issubclass(type(buffer), (bytes, bytearray)):
            buffer = buffer.decode()

        jwk = json.loads(buffer)

        curve = JWK_INVERSE_CURVE_LOOKUP[jwk['crv']]
        x = Bytes(url_b64_decode(jwk['x'].encode('utf-8'))).int()
        y = Bytes(url_b64_decode(jwk['y'].encode('utf-8'))).int()

        if 'd' in jwk:
            d = Bytes(url_b64_decode(jwk['d'].encode('utf-8'))).int()
        else:
            d = 0


        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = curve(x, y)
        return JWKECPublicKey(ecdsa)
