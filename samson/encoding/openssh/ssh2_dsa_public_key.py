from samson.encoding.openssh.core.dsa_public_key import DSAPublicKey
from samson.encoding.openssh.openssh_dsa_private_key import SSH_PUBLIC_HEADER
from samson.encoding.openssh.openssh_dsa_public_key import OpenSSHDSAPublicKey
from samson.encoding.openssh.general import generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding

class SSH2DSAPublicKey(OpenSSHDSAPublicKey):
    DEFAULT_MARKER = 'SSH2 PUBLIC KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = True


    @staticmethod
    def encode(dsa_key: object, **kwargs):
        public_key = DSAPublicKey('public_key', dsa_key.p, dsa_key.q, dsa_key.g, dsa_key.y)
        encoded = generate_openssh_public_key_params(PKIEncoding.SSH2, SSH_PUBLIC_HEADER, public_key)

        return SSH2DSAPublicKey.transport_encode(encoded, **kwargs)
