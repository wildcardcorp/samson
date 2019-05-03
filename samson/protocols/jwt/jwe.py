from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.utilities.bytes import Bytes
from samson.protocols.jwt.jwa import JWA_ALG_MAP, JWAContentEncryptionAlg, JWAKeyEncryptionAlg
import json


class JWE(object):
    """
    JSON Web Encryption
    """

    def __init__(self, header: bytes, encrypted_cek: bytes, iv: bytes, encrypted_body: bytes, auth_tag: bytes):
        """
        Parameters:
            header         (bytes): JWA algorithm to use for signing and verification.
            encrypted_cek  (bytes): Encrypted Content-Encrypting Key.
            iv             (bytes): Initialization vector.
            encrypted_body (bytes): Encrypted body.
            auth_tag       (bytes): Authentication tag.
        """
        self.header         = header
        self.encrypted_cek  = encrypted_cek
        self.iv             = iv
        self.encrypted_body = encrypted_body
        self.auth_tag      = auth_tag


    def __repr__(self):
        return f"<JWE: header={self.header}, encrypted_cek={self.encrypted_cek}, iv={self.iv}, encrypted_body={self.encrypted_body}, auth_tag={self.auth_tag}>"

    def __str__(self):
        return self.__repr__()


    def serialize(self) -> Bytes:
        """
        Serialize the JWE as bytes.

        Returns:
            Bytes: BASE64-URL encoded JWE.
        """
        return Bytes(b'.'.join([url_b64_encode(part) for part in [self.header, self.encrypted_cek, self.iv, self.encrypted_body, self.auth_tag]]))


    @staticmethod
    def parse(token: bytes) -> object:
        """
        Parses a bytestring `token` into a JWE object.

        Parameters:
            token (bytes): The JWE token to parse.
        
        Returns:
            JWE: JWE representation.
        """
        header, encrypted_cek, iv, body, auth_tag = [url_b64_decode(part) for part in token.split(b'.')]
        return JWE(header, encrypted_cek, iv, body, Bytes.wrap(auth_tag))


    @staticmethod
    def create(alg: JWAKeyEncryptionAlg, enc: JWAContentEncryptionAlg, body: bytes, key: object, **additional_headers) -> object:
        """
        Convenience method to create (and encrypt) a JWE.

        Parameters:
            alg                     (JWA): JWA algorithm to use for signing and verification.
            body                  (bytes): Body to be encrypted
            key                  (object): Key-encrypting key. Object type depending on the JWAKeyEncryptionAlg.
            **additional_headers (kwargs): Additional key-value pairs to place in JWE header.

        Returns:
            JWE: JWE representation.
        """
        header = {'typ': 'JWT', 'alg': alg.value, 'enc': enc.value}
        header.update(additional_headers)

        json_header = json.dumps(header).encode('utf-8')

        cek, iv                  = JWA_ALG_MAP[enc].generate_encryption_params()
        encrypted_body, auth_tag = JWA_ALG_MAP[enc].encrypt_and_auth(cek, iv, body, url_b64_encode(json_header))
        encrypted_cek            = JWA_ALG_MAP[alg].encrypt(key, cek)

        return JWE(json_header, encrypted_cek, iv, encrypted_body, auth_tag)



    def decrypt(self, key: object) -> Bytes:
        """
        Decrypts the JWE.

        Parameters:
            key (object): Object type depending on the JWAKeyEncryptionAlg.
        
        Returns:
            Bytes: The plaintext payload.
        """
        header = json.loads(self.header.decode())
        alg    = JWAKeyEncryptionAlg[header['alg'].replace('-', '_')]
        enc    = JWAContentEncryptionAlg[header['enc'].replace('-', '_')]

        cek    = JWA_ALG_MAP[alg].decrypt(key, self.encrypted_cek)
        return JWA_ALG_MAP[enc].decrypt(cek, self.iv, self.encrypted_body, url_b64_encode(self.header), self.auth_tag)
