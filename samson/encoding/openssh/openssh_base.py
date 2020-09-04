from samson.core.base_object import BaseObject
from samson.encoding.openssh.general import generate_openssh_private_key, parse_openssh_key

class OpenSSHPrivateBase(BaseObject):
    DEFAULT_MARKER = 'OPENSSH PRIVATE KEY'
    DEFAULT_PEM    = True

    PRIVATE_DECODER = None
    PUBLIC_DECODER  = None

    def __init__(self, key: object, user: bytes=b'nohost@localhost', **kwargs):
        self.key  = key

        if user and type(user) is str:
            user = user.encode('utf-8')

        self.user = user


    @classmethod
    def parse_keys(cls, buffer: bytes, passphrase: bytes=None):
        return parse_openssh_key(buffer, cls.SSH_PUBLIC_HEADER, cls.PUBLIC_DECODER, cls.PRIVATE_DECODER, passphrase)


    @classmethod
    def check(cls, buffer: bytes, passphrase: bytes=None, **kwargs):
        try:
            priv, _ = cls.parse_keys(buffer, passphrase)
            return priv is not None and cls.SSH_PUBLIC_HEADER in buffer
        except ValueError as _:
            return False


    def encode(self, encode_pem: bool=True, marker: str=None, encryption: bytes=None, iv: bytes=None, passphrase: bytes=None, **kwargs):
        public_key, private_key = self.build_keys(self.user)
        encoded = generate_openssh_private_key(public_key, private_key, encode_pem, marker, encryption, iv, passphrase)
        return encoded


    @classmethod
    def decode(cls, buffer: bytes, passphrase: bytes=None, **kwargs):
        return cls(cls.extract_key(*cls.parse_keys(buffer, passphrase)))



from samson.encoding.openssh.general import generate_openssh_public_key_params
from samson.encoding.pem import PEMEncodable
from samson.encoding.general import PKIEncoding

class OpenSSHPublicBase(OpenSSHPrivateBase, PEMEncodable):
    DEFAULT_MARKER = None
    DEFAULT_PEM    = False
    USE_RFC_4716   = False
    ENCODING       = PKIEncoding.OpenSSH
    PRIVATE_CLS    = None


    @classmethod
    def parameterize_header(cls, key: object):
        return cls.SSH_PUBLIC_HEADER


    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        return cls.SSH_PUBLIC_HEADER in buffer and not cls.PRIVATE_CLS.check(buffer)


    def encode(self, **kwargs) -> bytes:
        return self._actual_encode(self.user, encode_pem=False)


    def _actual_encode(self, user: bytes, **kwargs):
        public_key = self.build_pub()
        encoded    = generate_openssh_public_key_params(self.ENCODING, self.parameterize_header(public_key), public_key, user=user)
        return self.transport_encode(encoded, **kwargs)



class OpenSSH2PublicBase(OpenSSHPublicBase):
    DEFAULT_MARKER = 'SSH2 PUBLIC KEY'
    DEFAULT_PEM    = True
    USE_RFC_4716   = True
    ENCODING       = PKIEncoding.SSH2

    def encode(self, **kwargs) -> bytes:
        return self._actual_encode(None)
