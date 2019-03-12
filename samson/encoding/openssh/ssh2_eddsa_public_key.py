from samson.encoding.openssh.openssh_eddsa_private_key import SSH_PUBLIC_HEADER
from samson.encoding.openssh.openssh_eddsa_public_key import OpenSSHEdDSAPublicKey
from samson.encoding.openssh.core.eddsa_public_key import EdDSAPublicKey
from samson.encoding.openssh.general import generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding

class SSH2EdDSAPublicKey(OpenSSHEdDSAPublicKey):
    DEFAULT_MARKER = 'SSH2 PUBLIC KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = True


    @staticmethod
    def encode(eddsa_key: object, **kwargs):
        public_key = EdDSAPublicKey('public_key', eddsa_key.a)
        encoded = generate_openssh_public_key_params(PKIEncoding.SSH2, SSH_PUBLIC_HEADER, public_key)

        return SSH2EdDSAPublicKey.transport_encode(encoded, **kwargs)
