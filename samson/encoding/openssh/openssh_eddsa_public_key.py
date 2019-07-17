from samson.encoding.openssh.core.eddsa_private_key import EdDSAPrivateKey
from samson.encoding.openssh.core.eddsa_public_key import EdDSAPublicKey
from samson.encoding.openssh.openssh_eddsa_private_key import OpenSSHEdDSAPrivateKey, SSH_PUBLIC_HEADER
from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding
from samson.encoding.pem import PEMEncodable

class OpenSSHEdDSAPublicKey(PEMEncodable):
    DEFAULT_MARKER = None
    DEFAULT_PEM = False
    USE_RFC_4716 = False


    @staticmethod
    def check(buffer: bytes, **kwargs):
        return SSH_PUBLIC_HEADER in buffer and not OpenSSHEdDSAPrivateKey.check(buffer)


    @staticmethod
    def encode(eddsa_key: object, **kwargs):
        public_key = EdDSAPublicKey('public_key', eddsa_key.a)
        encoded = generate_openssh_public_key_params(PKIEncoding.OpenSSH, SSH_PUBLIC_HEADER, public_key, user=kwargs.get('user'))

        return OpenSSHEdDSAPublicKey.transport_encode(encoded, **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.eddsa import EdDSA
        from samson.math.algebra.curves.named import EdwardsCurve25519
        _, pub = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, EdDSAPublicKey, EdDSAPrivateKey, None)

        a, h = pub.a, 0
        eddsa = EdDSA(curve=EdwardsCurve25519, h=h, a=a, d=0, clamp=False)

        return eddsa
