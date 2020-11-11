from samson.encoding.general import url_b64_decode, url_b64_encode
from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import DecryptionException
from samson.protocols.jwt.jwa import JWA_ALG_MAP, JWAContentEncryptionAlg, JWAKeyEncryptionAlg
import json


class JWE(object):
    """
    JSON Web Encryption
    """

    def __init__(self, header: bytes, encrypted_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes):
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
        self.aad           = aad


    def __repr__(self):
        return f"<JWE: header={self.header}, jose_header={self.jose_header}, encrypted_key={self.encrypted_key}, iv={self.iv}, ciphertext={self.ciphertext}, tag={self.tag}, aad={self.aad}>"

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
    def parse(token: bytes) -> 'JWE':
        """
        Parses a compact bytestring `token` into a JWE object.

        Parameters:
            token (bytes): The JWE token to parse.
        
        Returns:
            JWE: JWE representation.
        """
        header, encrypted_key, iv, body, tag = [url_b64_decode(part) for part in token.split(b'.')]
        return JWE(header, encrypted_key, iv, body, Bytes.wrap(tag), None)


    @staticmethod
    def generate_cek(alg: JWAKeyEncryptionAlg, enc: JWAContentEncryptionAlg, key: object, header: dict, cek: bytes=None, iv: bytes=None) -> (object, bytes):
        generated_params = JWA_ALG_MAP[enc].generate_encryption_params()

        if alg == JWAKeyEncryptionAlg.dir:
            cek = key
        elif alg == JWAKeyEncryptionAlg.ECDH_ES:
            cek = JWA_ALG_MAP[alg].derive(key, len(generated_params[0]), header)

        cek, iv = [user_param or generated_param for user_param, generated_param in zip((cek, iv), generated_params)]
        return cek, iv


    @staticmethod
    def create(alg: JWAKeyEncryptionAlg, enc: JWAContentEncryptionAlg, body: bytes, key: object, cek: bytes=None, iv: bytes=None, aad: bytes=None, **additional_headers) -> 'JWE':
        """
        Convenience method to create (and encrypt) a JWE.

        Parameters:
            alg     (JWAKeyEncryptionAlg): JWA algorithm for key encryption.
            enc (JWAContentEncryptionAlg): JWA algorithm for content encryption.
            body                  (bytes): Body to be encrypted.
            key                  (object): Key-encrypting key. Object type depending on the JWAKeyEncryptionAlg.
            cek                   (bytes): Content-encrypting key for JWAContentEncryptionAlg. Random key will be generated if not specified.
            iv                    (bytes): IV for JWAContentEncryptionAlg. Random key will be generated if not specified.
            **additional_headers (kwargs): Additional key-value pairs to place in JWE header.

        Returns:
            JWE: JWE representation.
        """
        header = {'alg': alg.value, 'enc': enc.value}
        header.update(JWA_ALG_MAP[alg].generate_encryption_params())
        header.update(additional_headers)

        cek, iv = JWE.generate_cek(alg, enc, key, header, cek, iv)

        encrypted_key   = JWA_ALG_MAP[alg].encrypt(key, cek, header)
        json_header     = json.dumps(header, separators=(',', ':')).encode('utf-8')
        full_aad        = url_b64_encode(json_header) + b'.' + url_b64_encode(aad) if aad else url_b64_encode(json_header)
        ciphertext, tag = JWA_ALG_MAP[enc].encrypt_and_auth(cek, iv, body, full_aad)

        return JWE(json_header, encrypted_key, iv, ciphertext, tag, aad)


    @property
    def alg(self):
        alg = JWAKeyEncryptionAlg[self.jose_header['alg'].replace('+', '_plus_').replace('-', '_')]
        return alg


    @property
    def enc(self):
        header = json.loads(self.header.decode())
        enc    = JWAContentEncryptionAlg[header['enc'].replace('-', '_')]
        return enc


    @property
    def jose_header(self):
        header = json.loads(self.header.decode())
        if hasattr(self, 'unprotected_header'):
            header.update(self.unprotected_header)

        return header


    def decrypt(self, key: object) -> Bytes:
        """
        Decrypts the JWE.

        Parameters:
            key (object): Object type depending on the JWAKeyEncryptionAlg.
        
        Returns:
            Bytes: The plaintext payload.
        """
        aad  = url_b64_encode(self.header) + b'.' + url_b64_encode(self.aad) if self.aad else url_b64_encode(self.header)
        cek  = JWA_ALG_MAP[self.alg].decrypt(key, self.encrypted_key, self.jose_header)
        return JWA_ALG_MAP[self.enc].decrypt(cek, self.iv, self.ciphertext, aad, self.tag)




class JWESet(object):
    def __init__(self, enc: JWAContentEncryptionAlg, ciphertext: bytes, tag: bytes, cek: bytes, iv: bytes, protected_header: bytes, payload: bytes=None, recipients: list=None, unprotected_header: dict=None, aad: bytes=None):
        """
        Parameters:
            enc (JWAContentEncryptionAlg): Algorithm used to encrypt the payload.
            ciphertext            (bytes): Ciphertext representation of the payload.
            tag                   (bytes): Authentication tag for JWAContentEncryptionAlg.
            cek                   (bytes): Content encryption key for JWAContentEncryptionAlg.
            iv                    (bytes): Initialization for JWAContentEncryptionAlg.
            payload               (bytes): Payload to be encrypted by all keys.
            recipients             (list): List of recipients to initialize with.
            unprotected_header     (dict): Unprotected header to include with the JWE.
            aad                   (bytes): Additional authenticated data.
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
        self.aad                = aad

        self.i_know_what_im_doing = False


    def __repr__(self):
        return f"<JWESet: payload={self.payload}, enc={self.enc}, cek={self.cek}, iv={self.iv}, aad={self.aad}, protected_header={self.protected_header}, unprotected_header={self.unprotected_header}, ciphertext={self.ciphertext}, recipients={self.recipients}>"

    def __str__(self):
        return self.__repr__()



    @staticmethod
    def create(enc: JWAContentEncryptionAlg, payload: bytes, cek: bytes=None, iv: bytes=None, aad: bytes=None, additional_protected_headers: dict=None, unprotected_header: dict=None) -> 'JWESet':
        """
        Creates a new JWESet.

        Parameters:
            enc       (JWAContentEncryptionAlg): Algorithm used to encrypt the payload.
            payload                     (bytes): Payload to be encrypted by all keys.
            cek                         (bytes): Content encryption key for JWAContentEncryptionAlg.
            aad                         (bytes): Additional authenticated data.
            iv                          (bytes): Initialization for JWAContentEncryptionAlg.
            recipients                   (list): List of recipients to initialize with.
            additional_protected_headers (dict): Additional values to put in the protected header.
            unprotected_header           (dict): Unprotected header to include with the JWE.
        
        Returns:
            JWESet: JWESet representation.
            
        """
        cek, iv          = JWE.generate_cek(alg=None, enc=enc, key=None, header=None, cek=cek, iv=iv)
        protected_header = {'enc': enc.value}
        protected_header.update(additional_protected_headers or {})

        json_header     = json.dumps(protected_header, separators=(',', ':')).encode('utf-8')
        full_aad        = url_b64_encode(json_header) + b'.' + url_b64_encode(aad) if aad else url_b64_encode(json_header)
        ciphertext, tag = JWA_ALG_MAP[enc].encrypt_and_auth(cek, iv, payload, full_aad)

        return JWESet(enc=enc, cek=cek, iv=iv, ciphertext=ciphertext, tag=tag, payload=payload, protected_header=json_header, unprotected_header=unprotected_header, aad=aad)



    def serialize(self, flatten: bool=False) -> bytes:
        """
        Serializes the JWESet into a JSON object via https://tools.ietf.org/html/rfc7515#section-3.2.

        Parameters:
            flatten (bool): Whether or not to flatten the structure if there's only one recipient.
        
        Returns:
            bytes: JSON encoding as bytes.
        """
        json_set = {
            'protected':  url_b64_encode(self.protected_header).decode(),
            'recipients': [{'header': jwe.unprotected_header, 'encrypted_key': url_b64_encode(jwe.encrypted_key).decode()} for jwe in self.recipients],
            'iv':         url_b64_encode(self.iv).decode(),
            'ciphertext': url_b64_encode(self.ciphertext).decode(),
            'tag':        url_b64_encode(self.tag).decode()
        }

        if self.unprotected_header:
            json_set['unprotected'] = url_b64_encode(json.dumps(self.unprotected_header, separators=(',', ':')).encode('utf-8')).decode()

        if self.aad:
            json_set['aad'] = url_b64_encode(self.aad).decode()

        if flatten and len(json_set['recipients']) == 1:
            json_set.update(json_set['recipients'][0])
            del json_set['recipients']

        return json.dumps(json_set, separators=(',', ':')).encode('utf-8')



    def add_recipient(self, alg: JWAKeyEncryptionAlg, key: object, **additional_headers):
        """
        Adds a JWE to the set.

        Parameters:
            alg         (JWAKeyEncryptionAlg): JWA key-encrypting to use for encryption.
            key                      (object): Encryption key. Object type depending on the JWAKeyEncryptionAlg.
            **additional_headers     (kwargs): Additional key-value pairs to place in JWE header.
        """
        unprotected_header = {'alg': alg.value}
        unprotected_header.update(additional_headers)

        if (alg in [JWAKeyEncryptionAlg.dir, JWAKeyEncryptionAlg.ECDH_ES] or any([recip.alg in [JWAKeyEncryptionAlg.dir, JWAKeyEncryptionAlg.ECDH_ES] for recip in self.recipients])) and len(self.recipients) > 0 and not self.i_know_what_im_doing:
            raise ValueError(f"Cannot add a recipient using {alg} when there are other recipients. This is because {alg} is either Direct Key Agreement or Direct Encryption. Use the 'i_know_what_im_doing' flag to do it anyway.")


        jwe = JWE.create(alg, self.enc, self.payload, key, cek=self.cek, iv=self.iv, aad=self.aad, **additional_headers)

        unprotected_header.update(json.loads(jwe.header.decode()))
        del unprotected_header['enc']
        jwe.unprotected_header = unprotected_header

        self.recipients.append(jwe)



    @staticmethod
    def process_recipient(protected_header: bytes, recipient_dict: dict, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> JWE:
        """
        Internal method to decode recipients into individual JWEs.
        """
        jwe = JWE(protected_header, url_b64_decode(recipient_dict['encrypted_key'].encode('utf-8')), iv, ciphertext, tag, aad)
        jwe.unprotected_header = recipient_dict['header']
        return jwe



    @staticmethod
    def parse(token: bytes) -> 'JWESet':
        """
        Parses a JSON bytestring `token` into a JWESet object.

        Parameters:
            token (bytes): The JWESet token to parse.
        
        Returns:
            JWESet: JWESet representation.
        """
        token_dict         = json.loads(token.decode())
        unprotected_header = None
        aad                = None

        if 'unprotected' in token_dict:
            unprotected_header = token_dict['unprotected']

        if 'aad' in token_dict:
            aad = url_b64_decode(token_dict['aad'].encode('utf-8'))

        protected_header      = url_b64_decode(token_dict['protected'].encode('utf-8'))
        protected_header_dict = json.loads(protected_header.decode())
        ciphertext            = url_b64_decode(token_dict['ciphertext'].encode('utf-8'))
        iv                    = url_b64_decode(token_dict['iv'].encode('utf-8'))
        tag                   = url_b64_decode(token_dict['tag'].encode('utf-8'))

        # Is this a flattened token?
        if 'encrypted_key' in token_dict:
            recipients = [JWESet.process_recipient(protected_header, token_dict, iv, ciphertext, tag, aad)]
        else:
            recipients = [JWESet.process_recipient(protected_header, jwe_dict, iv, ciphertext, tag, aad) for jwe_dict in token_dict['recipients']]

        return JWESet(enc=JWAContentEncryptionAlg[protected_header_dict['enc'].replace('-', '_')], ciphertext=ciphertext, tag=tag, cek=None, iv=iv, payload=None, recipients=recipients, protected_header=protected_header, unprotected_header=unprotected_header, aad=aad)



    def decrypt(self, key: object, kid: str=None) -> Bytes:
        """
        Decrypts the ciphertext. If `kid` is not specified, all encrypted keys are tried.

        Parameters:
            key (object): Decryption key with object type depending on the JWAKeyEncryptionAlg.
            kid    (str): (Optional) 'kid' in unprotected header that identifies the encrypted_key.

        Returns:
            Bytes: Plaintext.
        """
        if kid:
            plaintext = [jwe for jwe in self.recipients if 'kid' in jwe.unprotected_header and jwe.unprotected_header['kid'] == kid][0].decrypt(key)
        else:
            plaintext = None
            for recipient in self.recipients:
                try:
                    plaintext = recipient.decrypt(key)
                    break
                except Exception as _:
                    pass

            if not plaintext:
                raise DecryptionException('No recipient able to decrypt.')

        return plaintext
