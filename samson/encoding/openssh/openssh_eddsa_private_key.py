from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_private_key
from samson.encoding.openssh.core.eddsa_private_key import EdDSAPrivateKey
from samson.encoding.openssh.core.eddsa_public_key import EdDSAPublicKey

SSH_PUBLIC_HEADER = b'ssh-ed25519'

class OpenSSHEdDSAPrivateKey(object):
    DEFAULT_MARKER = 'OPENSSH PRIVATE KEY'
    DEFAULT_PEM = True

    @staticmethod
    def check(buffer: bytes, **kwargs):
        try:
            priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, EdDSAPublicKey, EdDSAPrivateKey, kwargs.get('passphrase'))
            return priv is not None and SSH_PUBLIC_HEADER in buffer
        except ValueError as _:
            return False


    @staticmethod
    def encode(eddsa_key: object, **kwargs):
        user = kwargs.get('user')
        if user and type(user) is str:
            user = user.encode('utf-8')

        public_key  = EdDSAPublicKey('public_key', eddsa_key.a)
        private_key = EdDSAPrivateKey(
            'private_key',
            check_bytes=None,
            a=eddsa_key.a,
            h=eddsa_key.h,
            host=user or b'nohost@localhost'
        )

        encoded = generate_openssh_private_key(public_key, private_key, kwargs.get('encode_pem'), kwargs.get('marker'), kwargs.get('encryption'), kwargs.get('iv'), kwargs.get('passphrase'))
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.eddsa import EdDSA
        from samson.math.algebra.curves.named import EdwardsCurve25519
        priv, _ = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, EdDSAPublicKey, EdDSAPrivateKey, kwargs.get('passphrase'))

        a, h = priv.a, priv.h
        eddsa = EdDSA(curve=EdwardsCurve25519, h=h, a=a, d=0, clamp=False)

        return eddsa
