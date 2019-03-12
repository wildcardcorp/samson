from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_private_key
from samson.encoding.openssh.core.dsa_private_key import DSAPrivateKey
from samson.encoding.openssh.core.dsa_public_key import DSAPublicKey

SSH_PUBLIC_HEADER = b'ssh-dss'

class OpenSSHDSAPrivateKey(object):
    DEFAULT_MARKER = 'OPENSSH PRIVATE KEY'
    DEFAULT_PEM = True

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, DSAPublicKey, DSAPrivateKey, kwargs.get('passphrase'))
            return priv is not None and SSH_PUBLIC_HEADER in buffer
        except ValueError as _:
            return False


    @staticmethod
    def encode(dsa_key: object, **kwargs):
        user = kwargs.get('user')
        if user and type(user) is str:
            user = user.encode('utf-8')

        public_key  = DSAPublicKey('public_key', dsa_key.p, dsa_key.q, dsa_key.g, dsa_key.y)
        private_key = DSAPrivateKey(
            'private_key',
            check_bytes=None,
            p=dsa_key.p,
            q=dsa_key.q,
            g=dsa_key.g,
            y=dsa_key.y,
            x=dsa_key.x,
            host=user or b'nohost@localhost'
        )

        encoded = generate_openssh_private_key(public_key, private_key, kwargs.get('encode_pem'), kwargs.get('marker'), kwargs.get('encryption'), kwargs.get('iv'), kwargs.get('passphrase'))
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.dsa import DSA
        priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, DSAPublicKey, DSAPrivateKey, kwargs.get('passphrase'))

        p, q, g, y, x = priv.p, priv.q, priv.g, priv.y, priv.x

        dsa = DSA(None, p=p, q=q, g=g, x=x)
        dsa.y = y

        return dsa
