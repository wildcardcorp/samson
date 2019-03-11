from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_private_key
from samson.encoding.openssh.core.ecdsa_private_key import ECDSAPrivateKey
from samson.encoding.openssh.core.ecdsa_public_key import ECDSAPublicKey
from samson.utilities.bytes import Bytes
from fastecdsa.curve import P192, P224, P256, P384, P521
from fastecdsa.point import Point
import math

SSH_PUBLIC_HEADER = b'ecdsa-'

SSH_CURVE_NAME_LOOKUP = {
    P192: b'nistp192',
    P224: b'nistp224',
    P256: b'nistp256',
    P384: b'nistp384',
    P521: b'nistp521'
}

SSH_INVERSE_CURVE_LOOKUP = {v.decode():k for k, v in SSH_CURVE_NAME_LOOKUP.items()}

def seriailize_public_point(ecdsa_key: object):
    curve = SSH_CURVE_NAME_LOOKUP[ecdsa_key.G.curve]
    zero_fill = math.ceil(ecdsa_key.G.curve.q.bit_length() / 8)
    x_y_bytes = b'\x04' + (Bytes(ecdsa_key.Q.x).zfill(zero_fill) + Bytes(ecdsa_key.Q.y).zfill(zero_fill))

    return curve, x_y_bytes



class OpenSSHECDSAPrivateKey(object):
    DEFAULT_MARKER = 'OPENSSH PRIVATE KEY'
    DEFAULT_PEM = True

    @staticmethod
    def check(buffer: bytes, passphrase: bytes=None):
        try:
            priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, ECDSAPublicKey, ECDSAPrivateKey, passphrase)
            return priv is not None
        except ValueError as _:
            return False


    @staticmethod
    def encode(ecdsa_key: object, encode_pem=None, marker=None, encryption=None, iv=None, passphrase=None):
        curve, x_y_bytes = seriailize_public_point(ecdsa_key)

        public_key = ECDSAPublicKey('public_key', curve, x_y_bytes)
        private_key = ECDSAPrivateKey(
            'private_key',
            check_bytes=None,
            curve=curve,
            x_y_bytes=x_y_bytes,
            d=ecdsa_key.d,
            host=b'nohost@localhost'
        )

        encoded = generate_openssh_private_key(public_key, private_key, encode_pem, marker, encryption, iv, passphrase)
        return encoded


    @staticmethod
    def decode(buffer: bytes, passphrase: bytes=None):
        from samson.public_key.ecdsa import ECDSA
        priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, ECDSAPublicKey, ECDSAPrivateKey, passphrase)

        curve, x_y_bytes, d = priv.curve, priv.x_y_bytes, priv.d
        curve = SSH_INVERSE_CURVE_LOOKUP[curve.decode()]

        Q = Point(*ECDSA.decode_point(x_y_bytes), curve)
        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = Q

        return ecdsa
