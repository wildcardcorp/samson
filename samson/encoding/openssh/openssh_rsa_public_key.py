from samson.encoding.openssh.core.rsa_private_key import RSAPrivateKey
from samson.encoding.openssh.core.rsa_public_key import RSAPublicKey
from samson.encoding.openssh.openssh_rsa_private_key import OpenSSHRSAPrivateKey, SSH_PUBLIC_HEADER
from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding
from samson.encoding.pem import PEMEncodable

class OpenSSHRSAPublicKey(PEMEncodable):
    DEFAULT_MARKER = None
    DEFAULT_PEM = False
    USE_RFC_4716 = False


    @staticmethod
    def check(buffer: bytes, **kwargs):
        return SSH_PUBLIC_HEADER in buffer and not OpenSSHRSAPrivateKey.check(buffer)


    @staticmethod
    def encode(rsa_key: object, **kwargs):
        public_key = RSAPublicKey('public_key', rsa_key.n, rsa_key.e)
        encoded = generate_openssh_public_key_params(PKIEncoding.OpenSSH, SSH_PUBLIC_HEADER, public_key, user=kwargs.get('user'))

        return OpenSSHRSAPublicKey.transport_encode(encoded, **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.rsa import RSA
        _, pub = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, RSAPublicKey, RSAPrivateKey, None)

        n, e, p, q = pub.n, pub.e, 2, 3

        rsa = RSA(8, p=p, q=q, e=e)
        rsa.n = n

        return rsa
