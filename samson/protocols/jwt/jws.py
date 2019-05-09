from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.utilities.bytes import Bytes
from samson.protocols.jwt.jwa import JWA_ALG_MAP, JWASignatureAlg
import json


class JWS(object):
    """
    JSON Web Signature
    """

    def __init__(self, header: bytes, body: bytes, signature: bytes):
        """
        Parameters:
            header    (bytes): JWS JSON header.
            body      (bytes): Body to be signed or verified.
            signature (bytes): Signature value.
        """
        self.header    = header
        self.body      = body
        self.signature = signature


    def __repr__(self):
        return f"<JWS: header={self.header}, body={self.body}, signature={self.signature}>"

    def __str__(self):
        return self.__repr__()



    def serialize(self) -> Bytes:
        """
        Serialize the JWS into its compact representation.

        Returns:
            Bytes: BASE64-URL encoded JWS.
        """
        return Bytes(b'.'.join([url_b64_encode(part) for part in [self.header, self.body, self.signature]]))


    @staticmethod
    def parse(token: bytes) -> object:
        """
        Parses a compact bytestring `token` into a JWS object.

        Parameters:
            token (bytes): The JWS token to parse.
        
        Returns:
            JWS: JWS representation.
        """
        header, body, signature = [url_b64_decode(part) for part in token.split(b'.')]
        return JWS(header, body, Bytes.wrap(signature))


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
        header = {'alg': alg.value}
        header.update(additional_headers)

        json_header = json.dumps(header).encode('utf-8')
        jws = JWS(json_header, body, b'')
        jws.recompute_signature(key)
        return jws


    def recompute_signature(self, key: object):
        """
        Recomputes the signature given a `key`.

        Parameters:
            key (object): Signing key. Object type depending on the JWASignatureAlg.
        """
        self.signature = JWA_ALG_MAP[self.alg].sign(key, url_b64_encode(self.header) + b'.' + url_b64_encode(self.body))


    @property
    def alg(self):
        return JWASignatureAlg[json.loads(self.header.decode())['alg']]


    def verify(self, key: object) -> bool:
        """
        Verifies the signature on the JWS.

        Parameters:
            key (object): Verification key with object type depending on the JWASignatureAlg.
        
        Returns:
            bool: Whether or not it passed verification.
        """
        data = url_b64_encode(self.header) + b'.' + url_b64_encode(self.body)
        return JWA_ALG_MAP[self.alg].verify(key, data, self.signature)



class JWSSet(object):
    def __init__(self, payload: bytes, signatures: list=None):
        """
        Parameters:
            payload   (bytes): Payload to be signed by all signatures.
            signatures (list): (Optional) List of signatures to initialize with.
        """
        self.payload    = payload
        self.signatures = signatures or []


    def __repr__(self):
        return f"<JWSSet: payload={self.payload}, signatures={self.signatures}>"

    def __str__(self):
        return self.__repr__()


    def serialize(self, flatten: bool=False) -> bytes:
        """
        Serializes the JWSSet into a JSON object via https://tools.ietf.org/html/rfc7515#section-3.2.

        Parameters:
            flatten (bool): Whether or not to flatten the structure if there's only one signature.
        
        Returns:
            bytes: JSON encoding as bytes.
        """
        json_set = {
            'payload': url_b64_encode(self.payload).decode(),
            'signatures': [{'protected': url_b64_encode(jws.header).decode(), 'header': unprotected_header, 'signature': url_b64_encode(jws.signature).decode()} for jws, unprotected_header in self.signatures]
        }

        if flatten and len(json_set['signatures']) == 1:
            json_set.update(json_set['signatures'][0])
            del json_set['signatures']

        return json.dumps(json_set).encode('utf-8')


    def add_signature(self, alg: JWASignatureAlg, kid: str, key: object, unprotected_header: dict=None, **additional_headers):
        """
        Adds a signature to the set.

        Parameters:
            alg         (JWASignatureAlg): JWA signature algorithm to use for signing and verification.
            kid                     (str): 'kid' in unprotected header that identifies the key.
            key                  (object): Signing key. Object type depending on the JWASignatureAlg.
            unprotected_header     (dict): Unprotected header to include with the JWS.
            **additional_headers (kwargs): Additional key-value pairs to place in JWS header.
        """
        unprotected_header = unprotected_header or {}
        unprotected_header.update({'kid': kid})

        self.signatures.append((JWS.create(alg, self.payload, key, **additional_headers), unprotected_header))


    @staticmethod
    def parse(token: bytes) -> object:
        """
        Parses a JSON bytestring `token` into a JWSSet object.

        Parameters:
            token (bytes): The JWSSet token to parse.
        
        Returns:
            JWSSet: JWSSet representation.
        """
        token_dict = json.loads(token.decode())
        payload    = url_b64_decode(token_dict['payload'].encode('utf-8'))

        # Is this a flattened token?
        if 'signature' in token_dict:
            jws    = JWS(url_b64_decode(token_dict['protected'].encode('utf-8')), payload, url_b64_decode(token_dict['signature'].encode('utf-8')))
            jwsset = JWSSet(payload, [(jws, token_dict['header'])])
        else:
            jwsset = JWSSet(payload)
            for jws_dict in token_dict['signatures']:
                jws = JWS(url_b64_decode(jws_dict['protected'].encode('utf-8')), payload, url_b64_decode(jws_dict['signature'].encode('utf-8')))
                jwsset.signatures.append((jws, jws_dict['header']))

        return jwsset


    def verify(self, kid: str, key: object) -> bool:
        """
        Verifies a signature with `kid` in the JWSSet.

        Parameters:
            kid    (str): 'kid' in unprotected header that identifies the signature.
            key (object): Verification key with object type depending on the JWASignatureAlg.

        Returns:
            bool: Whether or not it passed verification.
        """
        return [sig for sig in self.signatures if 'kid' in sig[1] and sig[1]['kid'] == kid][0][0].verify(key)
