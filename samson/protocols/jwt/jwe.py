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
        self.auth_tag       = auth_tag


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
    def create(alg: JWAKeyEncryptionAlg, enc: JWAContentEncryptionAlg, body: bytes, key: object, cek: bytes=None, iv: bytes=None, **additional_headers) -> object:
        """
        Convenience method to create (and encrypt) a JWE.

        Parameters:
            alg                     (JWA): JWA algorithm to use for signing and verification.
            body                  (bytes): Body to be encrypted
            key                  (object): Key-encrypting key. Object type depending on the JWAKeyEncryptionAlg.
            cek                   (bytes): Content-encrypting key for JWAContentEncryptionAlg. Random key will be generated if not specified.
            iv                    (bytes): IV for JWAContentEncryptionAlg. Random key will be generated if not specified.
            **additional_headers (kwargs): Additional key-value pairs to place in JWE header.

        Returns:
            JWE: JWE representation.
        """
        header = {'typ': 'JWT', 'alg': alg.value, 'enc': enc.value}
        header.update(JWA_ALG_MAP[alg].generate_encryption_params())
        header.update(additional_headers)

        generated_params = JWA_ALG_MAP[enc].generate_encryption_params()

        if alg == JWAKeyEncryptionAlg.dir:
            cek = key
        elif alg == JWAKeyEncryptionAlg.ECDH_ES:
            cek = JWA_ALG_MAP[alg].derive(key, len(generated_params[0]), header)

        cek, iv = [user_param or generated_param for user_param, generated_param in zip((cek, iv), generated_params)]

        encrypted_cek            = JWA_ALG_MAP[alg].encrypt(key, cek, header)
        json_header              = json.dumps(header).encode('utf-8')
        encrypted_body, auth_tag = JWA_ALG_MAP[enc].encrypt_and_auth(cek, iv, body, url_b64_encode(json_header))

        return JWE(json_header, encrypted_cek, iv, encrypted_body, auth_tag)


    @property
    def alg(self):
        header = json.loads(self.header.decode())
        alg    = JWAKeyEncryptionAlg[header['alg'].replace('+', '_plus_').replace('-', '_')]
        return alg


    @property
    def enc(self):
        header = json.loads(self.header.decode())
        enc    = JWAContentEncryptionAlg[header['enc'].replace('-', '_')]
        return enc


    def decrypt(self, key: object) -> Bytes:
        """
        Decrypts the JWE.

        Parameters:
            key (object): Object type depending on the JWAKeyEncryptionAlg.
        
        Returns:
            Bytes: The plaintext payload.
        """
        cek  = JWA_ALG_MAP[self.alg].decrypt(key, self.encrypted_cek, json.loads(self.header.decode()))
        return JWA_ALG_MAP[self.enc].decrypt(cek, self.iv, self.encrypted_body, url_b64_encode(self.header), self.auth_tag)
