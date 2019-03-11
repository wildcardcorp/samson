from samson.encoding.openssh.core.eddsa_private_key import EdDSAPrivateKey
from samson.encoding.openssh.core.eddsa_public_key import EdDSAPublicKey
from samson.encoding.openssh.openssh_eddsa_private_key import OpenSSHEdDSAPrivateKey, SSH_PUBLIC_HEADER
from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding

class OpenSSHEdDSAPublicKey(object):
    DEFAULT_MARKER = None
    DEFAULT_PEM = False
    USE_RFC_4716 = False


    @staticmethod
    def check(buffer: bytes):
        return SSH_PUBLIC_HEADER in buffer and not OpenSSHEdDSAPrivateKey.check(buffer)


    @staticmethod
    def encode(eddsa_key: object):
        public_key = EdDSAPublicKey('public_key', eddsa_key.a)
        encoded, _, _, _ = generate_openssh_public_key_params(PKIEncoding.OpenSSH, SSH_PUBLIC_HEADER, public_key)

        return encoded


    @staticmethod
    def decode(buffer: bytes, passphrase: bytes=None):
        from samson.public_key.eddsa import EdDSA
        from samson.utilities.ecc import EdwardsCurve25519
        _, pub = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, EdDSAPublicKey, EdDSAPrivateKey, passphrase)

        a, h = pub.a, 0
        eddsa = EdDSA(curve=EdwardsCurve25519, h=h, a=a, d=0, clamp=False)

        return eddsa
