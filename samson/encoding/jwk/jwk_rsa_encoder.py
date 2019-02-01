from samson.utilities.bytes import Bytes
from samson.encoding.general import url_b64_decode, url_b64_encode
import json

class JWKRSAEncoder(object):
    """
    JWK encoder for RSA
    """

    @staticmethod
    def encode(rsa_key: object, is_private: bool=False) -> str:
        """
        Encodes the key as a JWK JSON string.

        Parameters:
            rsa_key     (RSA): RSA key to encode.
            is_private (bool): Whether or not `rsa_key` is a private key and to encode private parameters.
        
        Returns:
            str: JWK JSON string.
        """
        jwk = {
            'kty': 'RSA',
            'n': url_b64_encode(Bytes(rsa_key.n)).decode(),
            'e': url_b64_encode(Bytes(rsa_key.e)).decode(),
        }

        if is_private:
            jwk['d']  = url_b64_encode(Bytes(rsa_key.alt_d)).decode()
            jwk['p']  = url_b64_encode(Bytes(rsa_key.p)).decode()
            jwk['q']  = url_b64_encode(Bytes(rsa_key.q)).decode()
            jwk['dp'] = url_b64_encode(Bytes(rsa_key.dP)).decode()
            jwk['dq'] = url_b64_encode(Bytes(rsa_key.dQ)).decode()
            jwk['qi'] = url_b64_encode(Bytes(rsa_key.Qi)).decode()

        return json.dumps(jwk)


    @staticmethod
    def decode(buffer: bytes) -> (int, int, int, int):
        """
        Decodes a JWK JSON string into ECDSA parameters.

        Parameters:
            buffer (bytes/str): JWK JSON string.
        
        Returns:
            (int, int, int, int): RSA parameters formatted as (n, e, p, q).
        """
        if type(buffer) is bytes:
            buffer = buffer.decode()

        jwk = json.loads(buffer)
        n = Bytes(url_b64_decode(jwk['n'].encode('utf-8'))).int()
        e = Bytes(url_b64_decode(jwk['e'].encode('utf-8'))).int()

        if 'p' in jwk:
            p = Bytes(url_b64_decode(jwk['p'].encode('utf-8'))).int()
            q = Bytes(url_b64_decode(jwk['q'].encode('utf-8'))).int()
        else:
            p = 2
            q = 3

        return n, e, p, q
