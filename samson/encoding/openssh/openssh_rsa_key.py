from samson.math.general import mod_inv
from samson.encoding.openssh.core.rsa_private_key import RSAPrivateKey
from samson.encoding.openssh.core.rsa_public_key import RSAPublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSH2PublicBase, OpenSSHPublicBase


class OpenSSHRSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = RSAPrivateKey
    PUBLIC_DECODER    = RSAPublicKey
    SSH_PUBLIC_HEADER = b'ssh-rsa'


    @classmethod
    def extract_key(cls, priv, pub):
        from samson.public_key.rsa import RSA

        n, e, p, q = pub.n, pub.e, priv.p if priv else 2, priv.q if priv else 3

        rsa   = RSA(n.bit_length(), p=p, q=q, e=e)
        rsa.n = n

        return rsa



class OpenSSHRSAPrivateKey(OpenSSHRSAKey):

    def build_keys(self, user):
        public_key  = RSAPublicKey('public_key', self.key.n, self.key.e)
        private_key = RSAPrivateKey(
            'private_key',
            check_bytes=None,
            n=self.key.n,
            e=self.key.e,
            d=self.key.alt_d,
            q_mod_p=mod_inv(self.key.q, self.key.p),
            p=self.key.p,
            q=self.key.q,
            host=user
        )

        return public_key, private_key



class OpenSSHRSAPublicKey(OpenSSHRSAKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHRSAPrivateKey

    def build_pub(self):
        return RSAPublicKey('public_key', self.key.n, self.key.e)



class SSH2RSAPublicKey(OpenSSHRSAPublicKey, OpenSSH2PublicBase):
    pass
