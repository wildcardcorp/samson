from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.utilities.bytes import Bytes
from samson.protocols.jwt.jwa import JWA_ALG_MAP, JWASignatureAlg
import json


class JWS(object):
    """
    JSON Web Signature
    """

    def __init__(self, header: bytes, body: bytes, sig: bytes):
        """
        Parameters:
            header (bytes): JWA algorithm to use for signing and verification.
            body   (bytes): Body to be signed or verified.
            sig    (bytes): Signature value.
        """
        self.header = header
        self.body   = body
        self.sig    = sig


    def __repr__(self):
        return f"<JWS: header={self.header}, body={self.body}, sig={self.sig}>"

    def __str__(self):
        return self.__repr__()



    def serialize(self) -> Bytes:
        """
        Serialize the JWS as bytes.

        Returns:
            Bytes: BASE64-URL encoded JWS.
        """
        return Bytes(b'.'.join([url_b64_encode(part) for part in [self.header, self.body, self.sig]]))


    @staticmethod
    def parse(token: bytes) -> object:
        """
        Parses a bytestring `token` into a JWS object.

        Parameters:
            token (bytes): The JWS token to parse.
        
        Returns:
            JWS: JWS representation.
        """
        header, body, sig = [url_b64_decode(part) for part in token.split(b'.')]
        return JWS(header, body, Bytes.wrap(sig))


    @staticmethod
    def create(alg: JWASignatureAlg, body: bytes, key: object, **additional_headers) -> object:
        """
        Convenience method to create (and sign) a JWS.

        Parameters:
            alg         (JWASignatureAlg): JWA signature algorithm to use for signing and verification.
            body                  (bytes): Body to be signed or verified.
            key                  (object): Signing key. Object type depending on the JWASignatureAlg.
            **additional_headers (kwargs): Additional key-value pairs to place in JWS header.

        Returns:
            JWS: JWS representation.
        """
        header = {'typ': 'JWT', 'alg': alg.value}
        header.update(additional_headers)

        json_header = json.dumps(header).encode('utf-8')
        jws = JWS(json_header, body, b'')
        jws.recompute_signature(key)
        return jws


    def recompute_signature(self, key: object):
        self.sig = JWA_ALG_MAP[self.alg].sign(key, url_b64_encode(self.header) + b'.' + url_b64_encode(self.body))


    @property
    def alg(self):
        return JWASignatureAlg[json.loads(self.header.decode())['alg']]


    def verify(self, key: object) -> bool:
        """
        Verifies the signature on the JWS.

        Parameters:
            key (object): Object type depending on the JWASignatureAlg.
        
        Returns:
            bool: Whether or not it passed verification.
        """
        data = url_b64_encode(self.header) + b'.' + url_b64_encode(self.body)
        return JWA_ALG_MAP[self.alg].verify(key, data, self.sig)
