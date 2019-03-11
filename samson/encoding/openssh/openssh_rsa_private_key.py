from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_private_key
from samson.utilities.math import mod_inv
from samson.encoding.openssh.core.rsa_private_key import RSAPrivateKey
from samson.encoding.openssh.core.rsa_public_key import RSAPublicKey

SSH_PUBLIC_HEADER = b'ssh-rsa'

class OpenSSHRSAPrivateKey(object):
    DEFAULT_MARKER = 'OPENSSH PRIVATE KEY'
    DEFAULT_PEM = True

    @staticmethod
    def check(buffer: bytes, passphrase: bytes=None):
        try:
            priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, RSAPublicKey, RSAPrivateKey, passphrase)
            return priv is not None
        except ValueError as _:
            return False


    @staticmethod
    def encode(rsa_key: object, encode_pem=None, marker=None, encryption=None, iv=None, passphrase=None):
        public_key  = RSAPublicKey('public_key', rsa_key.n, rsa_key.e)
        private_key = RSAPrivateKey(
            'private_key',
            check_bytes=None,
            n=rsa_key.n,
            e=rsa_key.e,
            d=rsa_key.alt_d,
            q_mod_p=mod_inv(rsa_key.q, rsa_key.p),
            p=rsa_key.p,
            q=rsa_key.q,
            host=b'nohost@localhost'
        )

        encoded = generate_openssh_private_key(public_key, private_key, encode_pem, marker, encryption, iv, passphrase)

        return encoded


    @staticmethod
    def decode(buffer: bytes, passphrase: bytes=None):
        from samson.public_key.rsa import RSA
        priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, RSAPublicKey, RSAPrivateKey, passphrase)

        n, e, p, q = priv.n, priv.e, priv.p, priv.q

        rsa = RSA(8, p=p, q=q, e=e)
        rsa.n = n

        return rsa
