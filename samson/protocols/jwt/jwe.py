from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.utilities.bytes import Bytes
from samson.protocols.jwt.jwa import JWA_ALG_MAP, JWAContentEncryptionAlg, JWAKeyEncryptionAlg
import json


class JWE(object):
    """
    JSON Web Encryption
    """

    def __init__(self, header: bytes, encrypted_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes):
        """
        Parameters:
            header        (bytes): JWE JSON header.
            encrypted_key (bytes): Encrypted Content-Encrypting Key.
            iv            (bytes): Initialization vector.
            ciphertext    (bytes): Encrypted body.
            tag           (bytes): Authentication tag.
        """
        self.header        = header
        self.encrypted_key = encrypted_key
        self.iv            = iv
        self.ciphertext    = ciphertext
        self.tag           = tag


    def __repr__(self):
        return f"<JWE: header={self.header}, encrypted_key={self.encrypted_key}, iv={self.iv}, ciphertext={self.ciphertext}, tag={self.tag}>"

    def __str__(self):
        return self.__repr__()


    def serialize(self) -> Bytes:
        """
        Serialize the JWE into its compact representation.

        Returns:
            Bytes: BASE64-URL encoded JWE.
        """
        return Bytes(b'.'.join([url_b64_encode(part) for part in [self.header, self.encrypted_key, self.iv, self.ciphertext, self.tag]]))


    @staticmethod
    def parse(token: bytes) -> object:
        """
        Parses a compact bytestring `token` into a JWE object.

        Parameters:
            token (bytes): The JWE token to parse.
        
        Returns:
            JWE: JWE representation.
        """
        header, encrypted_key, iv, body, tag = [url_b64_decode(part) for part in token.split(b'.')]
        return JWE(header, encrypted_key, iv, body, Bytes.wrap(tag))


    @staticmethod
    def generate_cek(alg: JWAKeyEncryptionAlg, enc: JWAContentEncryptionAlg, key: object, header: dict, cek: bytes=None, iv: bytes=None):
        generated_params = JWA_ALG_MAP[enc].generate_encryption_params()

        if alg == JWAKeyEncryptionAlg.dir:
            cek = key
        elif alg == JWAKeyEncryptionAlg.ECDH_ES:
            cek = JWA_ALG_MAP[alg].derive(key, len(generated_params[0]), header)

        cek, iv = [user_param or generated_param for user_param, generated_param in zip((cek, iv), generated_params)]
        return cek, iv


    @staticmethod
    def create(alg: JWAKeyEncryptionAlg, enc: JWAContentEncryptionAlg, body: bytes, key: object, cek: bytes=None, iv: bytes=None, include_alg_header: bool=True, **additional_headers) -> object:
        """
        Convenience method to create (and encrypt) a JWE.

        Parameters:
            alg                     (JWA): JWA algorithm for key encryption.
            enc                     (JWA): JWA algorithm for content encryption.
            body                  (bytes): Body to be encrypted.
            key                  (object): Key-encrypting key. Object type depending on the JWAKeyEncryptionAlg.
            cek                   (bytes): Content-encrypting key for JWAContentEncryptionAlg. Random key will be generated if not specified.
            iv                    (bytes): IV for JWAContentEncryptionAlg. Random key will be generated if not specified.
            **additional_headers (kwargs): Additional key-value pairs to place in JWE header.

        Returns:
            JWE: JWE representation.
        """
        header = {'enc': enc.value}

        if include_alg_header:
            header['alg'] = alg.value

        header.update(JWA_ALG_MAP[alg].generate_encryption_params())
        header.update(additional_headers)

        cek, iv = JWE.generate_cek(alg, enc, key, header, cek, iv)

        encrypted_key   = JWA_ALG_MAP[alg].encrypt(key, cek, header)
        json_header     = json.dumps(header).encode('utf-8')
        ciphertext, tag = JWA_ALG_MAP[enc].encrypt_and_auth(cek, iv, body, url_b64_encode(json_header))

        return JWE(json_header, encrypted_key, iv, ciphertext, tag)


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


    def decrypt(self, key: object, alg: JWAKeyEncryptionAlg=None) -> Bytes:
        """
        Decrypts the JWE.

        Parameters:
            key (object): Object type depending on the JWAKeyEncryptionAlg.
        
        Returns:
            Bytes: The plaintext payload.
        """
        cek  = JWA_ALG_MAP[alg or self.alg].decrypt(key, self.encrypted_key, json.loads(self.header.decode()))
        return JWA_ALG_MAP[self.enc].decrypt(cek, self.iv, self.ciphertext, url_b64_encode(self.header), self.tag)




class JWESet(object):
    def __init__(self, enc: JWAContentEncryptionAlg, ciphertext: bytes, tag: bytes, cek: bytes, iv: bytes, protected_header: bytes, payload: bytes=None, recipients: list=None, unprotected_header: dict=None):
        """
        Parameters:
            payload           (bytes): Payload to be signed by all signatures.
            recipients         (list): (Optional) List of recipients to initialize with.
            unprotected_header (dict): Unprotected header to include with the JWE.
        """
        self.payload            = payload
        self.recipients         = recipients or []
        self.enc                = enc
        self.cek                = cek
        self.iv                 = iv
        self.unprotected_header = unprotected_header
        self.protected_header   = protected_header
        self.ciphertext         = ciphertext
        self.tag                = tag


    def __repr__(self):
        return f"<JWESet: payload={self.payload}, enc={self.enc}, cek={self.cek}, iv={self.iv}, protected_header={self.protected_header}, unprotected_header={self.unprotected_header}, ciphertext={self.ciphertext}, recipients={self.recipients}>"

    def __str__(self):
        return self.__repr__()



    @staticmethod
    def create(enc: JWAContentEncryptionAlg, payload: bytes, cek: bytes=None, iv: bytes=None, additional_protected_headers: dict=None, unprotected_header: dict=None):
        cek, iv          = JWE.generate_cek(alg=None, enc=enc, key=None, header=None, cek=cek, iv=iv)
        protected_header = {'enc': enc.value}
        protected_header.update(additional_protected_headers or {})

        json_header     = json.dumps(protected_header).encode('utf-8')
        ciphertext, tag = JWA_ALG_MAP[enc].encrypt_and_auth(cek, iv, payload, url_b64_encode(json_header))

        return JWESet(enc=enc, cek=cek, iv=iv, ciphertext=ciphertext, tag=tag, payload=payload, protected_header=json_header, unprotected_header=unprotected_header)



    def serialize(self, flatten: bool=False) -> bytes:
        """
        Serializes the JWESet into a JSON object via https://tools.ietf.org/html/rfc7515#section-3.2.

        Parameters:
            flatten (bool): Whether or not to flatten the structure if there's only one signature.
        
        Returns:
            bytes: JSON encoding as bytes.
        """
        json_set = {
            'protected':  url_b64_encode(self.protected_header).decode(),
            'recipients': [{'header': unprotected_header, 'encrypted_key': url_b64_encode(jwe.encrypted_key).decode()} for jwe, unprotected_header in self.recipients],
            'iv':         url_b64_encode(self.iv).decode(),
            'ciphertext': url_b64_encode(self.ciphertext).decode(),
            'tag':        url_b64_encode(self.tag).decode()
        }

        if self.unprotected_header:
            json_set['unprotected'] = url_b64_encode(json.dumps(self.unprotected_header).encode('utf-8')).decode()

        if flatten and len(json_set['recipients']) == 1:
            json_set.update(json_set['recipients'][0])
            del json_set['recipients']

        return json.dumps(json_set).encode('utf-8')



    def add_recipient(self, alg: JWAKeyEncryptionAlg, kid: str, key: object, **additional_headers):
        """
        Adds a JWE to the set.

        Parameters:
            alg         (JWASignatureAlg): JWA signature algorithm to use for signing and verification.
            kid                     (str): 'kid' in unprotected header that identifies the key.
            key                  (object): Signing key. Object type depending on the JWASignatureAlg.
            **additional_headers (kwargs): Additional key-value pairs to place in JWE header.
        """
        unprotected_header = {}
        unprotected_header.update({'alg': alg.value, 'kid': kid})
        unprotected_header.update(additional_headers)

        jwe = JWE.create(alg, self.enc, self.payload, key, cek=self.cek, iv=self.iv, **additional_headers)
        self.recipients.append((jwe, unprotected_header))



    @staticmethod
    def process_recipient(protected_header: bytes, recipient_dict: dict, iv: bytes, ciphertext: bytes, tag: bytes) -> (JWE, dict):
        #header     = {'alg': recipient_dict['header']['alg']}
        #header.update(protected_header)
        #header     = json.dumps(protected_header).encode('utf-8')

        jwe        = JWE(protected_header, url_b64_decode(recipient_dict['encrypted_key'].encode('utf-8')), iv, ciphertext, tag)
        return (jwe, recipient_dict['header'])



    @staticmethod
    def parse(token: bytes) -> object:
        """
        Parses a JSON bytestring `token` into a JWESet object.

        Parameters:
            token (bytes): The JWESet token to parse.
        
        Returns:
            JWESet: JWESet representation.
        """
        token_dict         = json.loads(token.decode())
        unprotected_header = None

        if 'unprotected' in token_dict:
            unprotected_header = token_dict['unprotected']

        protected_header      = url_b64_decode(token_dict['protected'].encode('utf-8'))
        protected_header_dict = json.loads(protected_header.decode())
        ciphertext            = url_b64_decode(token_dict['ciphertext'].encode('utf-8'))
        iv                    = url_b64_decode(token_dict['iv'].encode('utf-8'))
        tag                   = url_b64_decode(token_dict['tag'].encode('utf-8'))

        # Is this a flattened token?
        if 'encrypted_key' in token_dict:
            recipients = [JWESet.process_recipient(protected_header, token_dict, iv, ciphertext, tag)]
        else:
            recipients = [JWESet.process_recipient(protected_header, jwe_dict, iv, ciphertext, tag) for jwe_dict in token_dict['recipients']]
                
        return JWESet(enc=JWAContentEncryptionAlg[protected_header_dict['enc'].replace('-', '_')], ciphertext=ciphertext, tag=tag, cek=None, iv=iv, payload=None, recipients=recipients, protected_header=protected_header, unprotected_header=unprotected_header)



    def decrypt(self, kid: str, key: object) -> bool:
        """
        Decrypts the ciphertext with `kid` in the JWESet.

        Parameters:
            kid    (str): 'kid' in unprotected header that identifies the encrypted_key.
            key (object): Decryption key with object type depending on the JWAKeyEncryptionAlg.

        Returns:
            bool: Whether or not it passed verification.
        """
        return [encrypted_key for encrypted_key in self.recipients if 'kid' in encrypted_key[1] and encrypted_key[1]['kid'] == kid][0][0].decrypt(key, self.enc)
