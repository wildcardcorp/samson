from samson.encoding.openssh.core.rsa_public_key import RSAPublicKey
from samson.encoding.openssh.openssh_rsa_private_key import SSH_PUBLIC_HEADER
from samson.encoding.openssh.openssh_rsa_public_key import OpenSSHRSAPublicKey
from samson.encoding.openssh.general import generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding

class SSH2RSAPublicKey(OpenSSHRSAPublicKey):
    DEFAULT_MARKER = 'SSH2 PUBLIC KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = True

    @staticmethod
    def encode(rsa_key: object, **kwargs):
        public_key = RSAPublicKey('public_key', rsa_key.n, rsa_key.e)
        encoded = generate_openssh_public_key_params(PKIEncoding.SSH2, SSH_PUBLIC_HEADER, public_key)

        return SSH2RSAPublicKey.transport_encode(encoded, **kwargs)
