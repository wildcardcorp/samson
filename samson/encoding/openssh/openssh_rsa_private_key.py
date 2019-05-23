from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_private_key
from samson.math.general import mod_inv
from samson.encoding.openssh.core.rsa_private_key import RSAPrivateKey
from samson.encoding.openssh.core.rsa_public_key import RSAPublicKey

SSH_PUBLIC_HEADER = b'ssh-rsa'

class OpenSSHRSAPrivateKey(object):
    DEFAULT_MARKER = 'OPENSSH PRIVATE KEY'
    DEFAULT_PEM = True

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, RSAPublicKey, RSAPrivateKey, kwargs.get('passphrase'))
            return priv is not None and SSH_PUBLIC_HEADER in buffer
        except ValueError as _:
            return False


    @staticmethod
    def encode(rsa_key: object, **kwargs):
        user = kwargs.get('user')
        if user and type(user) is str:
            user = user.encode('utf-8')

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
            host=user or b'nohost@localhost'
        )

        encoded = generate_openssh_private_key(public_key, private_key, kwargs.get('encode_pem'), kwargs.get('marker'), kwargs.get('encryption'), kwargs.get('iv'), kwargs.get('passphrase'))

        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.rsa import RSA
        priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, RSAPublicKey, RSAPrivateKey, kwargs.get('passphrase'))

        n, e, p, q = priv.n, priv.e, priv.p, priv.q

        rsa = RSA(8, p=p, q=q, e=e)
        rsa.n = n

        return rsa
