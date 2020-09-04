from samson.encoding.openssh.core.dsa_private_key import DSAPrivateKey
from samson.encoding.openssh.core.dsa_public_key import DSAPublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSHPublicBase, OpenSSH2PublicBase


class OpenSSHDSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = DSAPrivateKey
    PUBLIC_DECODER    = DSAPublicKey
    SSH_PUBLIC_HEADER = b'ssh-dss'


    @classmethod
    def extract_key(cls, priv, pub):
        from samson.public_key.dsa import DSA
        p, q, g, y, x = pub.p, pub.q, pub.g, pub.y, priv.x if priv else 0

        dsa = DSA(None, p=p, q=q, g=g, x=x)
        dsa.y = y

        return dsa



class OpenSSHDSAPrivateKey(OpenSSHDSAKey):

    def build_keys(self, user):
        public_key  = DSAPublicKey('public_key', self.key.p, self.key.q, self.key.g, self.key.y)
        private_key = DSAPrivateKey(
            'private_key',
            check_bytes=None,
            p=self.key.p,
            q=self.key.q,
            g=self.key.g,
            y=self.key.y,
            x=self.key.x,
            host=user
        )

        return public_key, private_key


class OpenSSHDSAPublicKey(OpenSSHDSAKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHDSAPrivateKey

    def build_pub(self):
        return DSAPublicKey('public_key', self.key.p, self.key.q, self.key.g, self.key.y)




class SSH2DSAPublicKey(OpenSSHDSAPublicKey, OpenSSH2PublicBase):
    pass
