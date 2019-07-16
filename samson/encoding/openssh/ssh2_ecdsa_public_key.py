from samson.encoding.openssh.core.ecdsa_public_key import ECDSAPublicKey
from samson.encoding.openssh.openssh_ecdsa_private_key import serialize_public_point
from samson.encoding.openssh.openssh_ecdsa_public_key import OpenSSHECDSAPublicKey
from samson.encoding.openssh.general import generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding

class SSH2ECDSAPublicKey(OpenSSHECDSAPublicKey):
    DEFAULT_MARKER = 'SSH2 PUBLIC KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = True


    @staticmethod
    def encode(ecdsa_key: object, **kwargs):
        curve, x_y_bytes = serialize_public_point(ecdsa_key)
        public_key = ECDSAPublicKey('public_key', curve, x_y_bytes)
        encoded = generate_openssh_public_key_params(PKIEncoding.SSH2, b'ecdsa-sha2-' + curve, public_key)

        return SSH2ECDSAPublicKey.transport_encode(encoded, **kwargs)
