from samson.encoding.openssh.core.eddsa_private_key import EdDSAPrivateKey
from samson.encoding.openssh.core.eddsa_public_key import EdDSAPublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSHPublicBase, OpenSSH2PublicBase

class OpenSSHEdDSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = EdDSAPrivateKey
    PUBLIC_DECODER    = EdDSAPublicKey
    SSH_PUBLIC_HEADER = b'ssh-ed25519'


    @classmethod
    def extract_key(cls, priv, pub):
        from samson.public_key.eddsa import EdDSA
        from samson.math.algebra.curves.named import EdwardsCurve25519

        a, h  = pub.a, priv.h if priv else 0
        eddsa = EdDSA(curve=EdwardsCurve25519, h=h, a=a, d=0, clamp=False)

        return eddsa



class OpenSSHEdDSAPrivateKey(OpenSSHEdDSAKey):

    def build_keys(self, user):
        public_key  = EdDSAPublicKey('public_key', self.key.a)
        private_key = EdDSAPrivateKey(
            'private_key',
            check_bytes=None,
            a=self.key.a,
            h=self.key.h,
            host=user
        )

        return public_key, private_key



class OpenSSHEdDSAPublicKey(OpenSSHEdDSAKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHEdDSAPrivateKey

    def build_pub(self):
        return EdDSAPublicKey('public_key', self.key.a)


class SSH2EdDSAPublicKey(OpenSSHEdDSAPublicKey, OpenSSH2PublicBase):
    pass
