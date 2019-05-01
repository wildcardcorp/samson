from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.utilities.bytes import Bytes
from samson.encoding.jwa import JWA_ALG_MAP, JWA
import json


def build_header(alg, additional_headers):
    header = {"typ": "JWT", "alg": alg.value}
    header.update(additional_headers)
    
    return header


class JWT(object):
    """
    JSON Web Token
    """

    # def __init__(self, alg: JWA, body: dict, sig: bytes, **additional_headers):
    def __init__(self, header: dict, body: dict, sig: bytes):
        """
        Parameters:
            alg                     (JWA): JWA algorithm to use for signing and verification.
            body                   (dict): Body to be signed or verified.
            sig                   (bytes): Signature value.
            **additional_headers (kwargs): Additional key-value pairs to place in JWT header.
        """
        #self.alg  = alg
        self.header = header
        self.body   = body
        #self.additional_headers  = additional_headers
        self.sig    = sig
    

    def __repr__(self):
        return f"<JWT: header={self.header}, body={self.body}, sig={self.sig}"#, additional_headers={self.additional_headers}>"

    def __str__(self):
        return self.__repr__()

    

    def encode(self) -> Bytes:
        """
        Encodes the JWT as bytes.

        Returns:
            Bytes: BASE64-URL encoded JWT.
        """
        #header = build_header(self.alg, self.additional_headers)
        str_header = self.header.copy()
        str_header['alg'] = str_header['alg'].value
        return Bytes(b'.'.join([url_b64_encode(part) for part in [json.dumps(str_header).encode('utf-8'), json.dumps(self.body).encode('utf-8'), self.sig]]))


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

        header = json.loads(decoded[0].decode())
        body   = json.loads(decoded[1].decode())

        header['alg'] = JWA[header['alg']]
        return JWT(header, body, Bytes.wrap(decoded[2]), **{k:v for k,v in header.items() if k not in ['alg', 'typ']})
    

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
        #header = build_header(alg, additional_headers)
        header = {'typ': 'JWT', 'alg': alg}
        header.update(additional_headers)

        str_header = header.copy()
        str_header['alg'] = str_header['alg'].value
        return JWT(header, body, JWA_ALG_MAP[alg].sign(key, url_b64_encode(json.dumps(str_header).encode('utf-8')) + b'.' + url_b64_encode(json.dumps(body).encode('utf-8'))))#, **additional_headers)
    

    def verify(self, key: object) -> bool:
        """
        Verifies the signature on the JWT.

        Parameters:
            key (object): Object type depending on the JWA.
        
        Returns:
            bool: Whether or not it passed verification.
        """
        str_header = self.header.copy()
        str_header['alg'] = str_header['alg'].value
        #header = build_header(self.alg, self.additional_headers)
        return JWA_ALG_MAP[self.header['alg']].verify(key, url_b64_encode(json.dumps(str_header).encode('utf-8')) + b'.' + url_b64_encode(json.dumps(self.body).encode('utf-8')), self.sig)