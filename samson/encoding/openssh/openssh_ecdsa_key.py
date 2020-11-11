from samson.encoding.openssh.core.ecdsa_private_key import ECDSAPrivateKey
from samson.encoding.openssh.core.ecdsa_public_key import ECDSAPublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSHPublicBase, OpenSSH2PublicBase
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import P192, P224, P256, P384, P521, GOD521
import math


SSH_CURVE_NAME_LOOKUP = {
    P192: b'nistp192',
    P224: b'nistp224',
    P256: b'nistp256',
    P384: b'nistp384',
    P521: b'nistp521',
    GOD521: b'nistp521'
}

SSH_INVERSE_CURVE_LOOKUP = {v.decode():k for k, v in SSH_CURVE_NAME_LOOKUP.items() if k != GOD521}

def serialize_public_point(ecdsa_key: 'ECDSA'):
    curve = SSH_CURVE_NAME_LOOKUP[ecdsa_key.G.curve]
    zero_fill = math.ceil(ecdsa_key.G.curve.q.bit_length() / 8)
    x_y_bytes = b'\x04' + (Bytes(int(ecdsa_key.Q.x)).zfill(zero_fill) + Bytes(int(ecdsa_key.Q.y)).zfill(zero_fill))

    return curve, x_y_bytes



class OpenSSHECDSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = ECDSAPrivateKey
    PUBLIC_DECODER    = ECDSAPublicKey
    SSH_PUBLIC_HEADER = b'ecdsa-'

    @classmethod
    def extract_key(cls, priv, pub):
        from samson.public_key.ecdsa import ECDSA

        curve, x_y_bytes, d = pub.curve, pub.x_y_bytes, priv.d if priv else 1
        curve = SSH_INVERSE_CURVE_LOOKUP[curve.decode()]

        ecdsa   = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = curve(*ECDSA.decode_point(x_y_bytes))

        return ecdsa



class OpenSSHECDSAPrivateKey(OpenSSHECDSAKey):

    def build_keys(self, user):
        curve, x_y_bytes = serialize_public_point(self.key)

        public_key  = ECDSAPublicKey('public_key', curve, x_y_bytes)
        private_key = ECDSAPrivateKey(
            'private_key',
            check_bytes=None,
            curve=curve,
            x_y_bytes=x_y_bytes,
            d=self.key.d,
            host=user
        )

        return public_key, private_key



class OpenSSHECDSAPublicKey(OpenSSHECDSAKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHECDSAPrivateKey

    @classmethod
    def parameterize_header(cls, key: object):
        return b'ecdsa-sha2-' + key.curve


    def build_pub(self):
        curve, x_y_bytes = serialize_public_point(self.key)
        return ECDSAPublicKey('public_key', curve, x_y_bytes)



class SSH2ECDSAPublicKey(OpenSSHECDSAPublicKey, OpenSSH2PublicBase):
    pass
