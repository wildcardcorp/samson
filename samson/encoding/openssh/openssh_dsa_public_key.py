from samson.encoding.openssh.core.dsa_private_key import DSAPrivateKey
from samson.encoding.openssh.core.dsa_public_key import DSAPublicKey
from samson.encoding.openssh.openssh_dsa_private_key import OpenSSHDSAPrivateKey, SSH_PUBLIC_HEADER
from samson.encoding.openssh.general import parse_openssh_key, generate_openssh_public_key_params
from samson.encoding.general import PKIEncoding

class OpenSSHDSAPublicKey(object):
    DEFAULT_MARKER = None
    DEFAULT_PEM = False
    USE_RFC_4716 = False

    @staticmethod
    def check(buffer: bytes):
        return SSH_PUBLIC_HEADER in buffer and not OpenSSHDSAPrivateKey.check(buffer)


    @staticmethod
    def encode(dsa_key: object):
        public_key = DSAPublicKey('public_key', dsa_key.p, dsa_key.q, dsa_key.g, dsa_key.y)
        encoded, _, _, _ = generate_openssh_public_key_params(PKIEncoding.OpenSSH, SSH_PUBLIC_HEADER, public_key)

        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.dsa import DSA
        _, pub = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, DSAPublicKey, DSAPrivateKey, None)

        p, q, g, y, x = pub.p, pub.q, pub.g, pub.y, 0

        dsa = DSA(None, p=p, q=q, g=g, x=x)
        dsa.y = y

        return dsa
