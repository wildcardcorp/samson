from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.utilities.bytes import Bytes
from samson.encoding.jwa import JWA_ALG_MAP, JWA
import json


class JWT(object):
    """
    JSON Web Token
    """

    def __init__(self, header: str, body: str, sig: bytes):
        """
        Parameters:
            alg   (str): JWA algorithm to use for signing and verification.
            body  (str): Body to be signed or verified.
            sig (bytes): Signature value.
        """
        self.header = header
        self.body   = body
        self.sig    = sig
    

    def __repr__(self):
        return f"<JWT: header={self.header}, body={self.body}, sig={self.sig}>"

    def __str__(self):
        return self.__repr__()

    

    def encode(self) -> Bytes:
        """
        Encodes the JWT as bytes.

        Returns:
            Bytes: BASE64-URL encoded JWT.
        """
        return Bytes(b'.'.join([url_b64_encode(part) for part in [self.header.encode('utf-8'), self.body.encode('utf-8'), self.sig]]))


    @staticmethod
    def parse(token: bytes) -> object:
        """
        Parses a bytestring `token` into a JWT object.

        Parameters:
            token (bytes): The JWT token to parse.
        
        Returns:
            JWT: JWT representation.
        """
        parts = token.split(b'.')
        decoded = [url_b64_decode(part) for part in parts]

        header = decoded[0].decode()
        body   = decoded[1].decode()

        return JWT(header, body, Bytes.wrap(decoded[2]))
    

    @staticmethod
    def create(alg: JWA, body: dict, key: object, **additional_headers) -> object:
        """
        Convenience method to create (and sign) a JWT.

        Parameters:
            alg                     (JWA): JWA algorithm to use for signing and verification.
            body                   (dict): Body to be signed or verified.
            key                  (object): Signing key. Object type depending on the JWA.
            **additional_headers (kwargs): Additional key-value pairs to place in JWT header.

        Returns:
            JWT: JWT representation.
        """
        header = {'typ': 'JWT', 'alg': alg}
        header.update(additional_headers)

        str_header = header.copy()
        str_header['alg'] = str_header['alg'].value

        str_header = json.dumps(str_header)
        str_body   = json.dumps(body)
        return JWT(str_header, str_body, JWA_ALG_MAP[alg].sign(key, url_b64_encode(str_header.encode('utf-8')) + b'.' + url_b64_encode(str_body.encode('utf-8'))))
    

    def verify(self, key: object) -> bool:
        """
        Verifies the signature on the JWT.

        Parameters:
            key (object): Object type depending on the JWA.
        
        Returns:
            bool: Whether or not it passed verification.
        """
        jwa  = JWA[json.loads(self.header)['alg']]
        data = url_b64_encode(self.header.encode('utf-8')) + b'.' + url_b64_encode(self.body.encode('utf-8'))
        return JWA_ALG_MAP[jwa].verify(key, data, self.sig)