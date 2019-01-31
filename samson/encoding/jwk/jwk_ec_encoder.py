from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_decode, url_b64_encode
from fastecdsa.curve import P192, P224, P256, P384, P521
import json

JWK_CURVE_NAME_LOOKUP = {
    P192: 'P-192',
    P224: 'P-224',
    P256: 'P-256',
    P384: 'P-384',
    P521: 'P-521'
}

JWK_INVERSE_CURVE_LOOKUP = {v:k for k, v in JWK_CURVE_NAME_LOOKUP.items()}


class JWKECEncoder(object):
    @staticmethod
    def encode(ec_key, is_private=False):
        jwk = {
            'kty': 'EC',
            'crv': JWK_CURVE_NAME_LOOKUP[ec_key.G.curve],
            'x': url_b64_encode(Bytes(ec_key.Q.x)).decode(),
            'y': url_b64_encode(Bytes(ec_key.Q.y)).decode(),
        }

        if is_private:
            jwk['d'] = url_b64_encode(Bytes(ec_key.d)).decode()

        return json.dumps(jwk)
    

    @staticmethod
    def decode(buffer):
        if type(buffer) is bytes:
            buffer = buffer.decode()
            
        jwk = json.loads(buffer)
        curve = JWK_INVERSE_CURVE_LOOKUP[jwk['crv']]
        x = Bytes(url_b64_decode(jwk['x'].encode('utf-8'))).int()
        y = Bytes(url_b64_decode(jwk['y'].encode('utf-8'))).int()

        if 'd' in jwk:
            d = Bytes(url_b64_decode(jwk['d'].encode('utf-8'))).int()
        else:
            d = 0

        return curve, x, y, d