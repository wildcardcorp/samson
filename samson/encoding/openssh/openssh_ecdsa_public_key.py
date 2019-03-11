from samson.encoding.openssh.core.ecdsa_private_key import ECDSAPrivateKey
from samson.encoding.openssh.core.ecdsa_public_key import ECDSAPublicKey
from samson.encoding.openssh.openssh_ecdsa_private_key import OpenSSHECDSAPrivateKey, SSH_PUBLIC_HEADER, SSH_INVERSE_CURVE_LOOKUP, seriailize_public_point
from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding
from fastecdsa.point import Point

class OpenSSHECDSAPublicKey(object):
    DEFAULT_MARKER = None
    DEFAULT_PEM = False
    USE_RFC_4716 = False


    @staticmethod
    def check(buffer: bytes):
        return SSH_PUBLIC_HEADER in buffer and not OpenSSHECDSAPrivateKey.check(buffer)


    @staticmethod
    def encode(ecdsa_key: object):
        curve, x_y_bytes = seriailize_public_point(ecdsa_key)
        public_key = ECDSAPublicKey('public_key', curve, x_y_bytes)
        encoded, _, _, _ = generate_openssh_public_key_params(PKIEncoding.OpenSSH, b'ecdsa-sha2-' + curve, public_key)

        return encoded



    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.ecdsa import ECDSA
        _, pub = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, ECDSAPublicKey, ECDSAPrivateKey, None)

        curve, x_y_bytes, d = pub.curve, pub.x_y_bytes, 1
        curve = SSH_INVERSE_CURVE_LOOKUP[curve.decode()]

        Q = Point(*ECDSA.decode_point(x_y_bytes), curve)
        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = Q

        return ecdsa
