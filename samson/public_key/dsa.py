from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes

from samson.encoding.openssh.openssh_dsa_private_key import OpenSSHDSAPrivateKey
from samson.encoding.openssh.openssh_dsa_public_key import OpenSSHDSAPublicKey
from samson.encoding.openssh.ssh2_dsa_public_key import SSH2DSAPublicKey
from samson.encoding.x509.x509_dsa_public_key import X509DSAPublicKey
from samson.encoding.pkcs1.pkcs1_dsa_private_key import PKCS1DSAPrivateKey
from samson.encoding.pkcs8.pkcs8_dsa_private_key import PKCS8DSAPrivateKey
from samson.encoding.x509.x509_dsa_certificate import X509DSACertificate
from samson.core.encodable_pki import EncodablePKI
from samson.encoding.general import PKIEncoding

from samson.hashes.sha2 import SHA256

class DSA(EncodablePKI):
    """
    Digital Signature Algorithm
    """

    PRIV_ENCODINGS = {
        PKIEncoding.OpenSSH: OpenSSHDSAPrivateKey,
        PKIEncoding.PKCS1: PKCS1DSAPrivateKey,
        PKIEncoding.PKCS8: PKCS8DSAPrivateKey
    }


    PUB_ENCODINGS = {
        PKIEncoding.OpenSSH: OpenSSHDSAPublicKey,
        PKIEncoding.SSH2: SSH2DSAPublicKey,
        PKIEncoding.X509_CERT: X509DSACertificate,
        PKIEncoding.X509: X509DSAPublicKey
    }

    def __init__(self, hash_obj: object=SHA256(), p: int=None, q: int=None, g: int=None, x: int=None, L: int=2048, N: int=256):
        """
        Parameters:
            hash_obj (object): Instantiated object with compatible hash interface.
            p           (int): (Optional) Prime modulus.
            q           (int): (Optional) Prime modulus.
            g           (int): (Optional) Generator.
            x           (int): (Optional) Private key.
        """
        self.p = p or 0x00c74772759167e757e0d33a6e2a2f2643f89f6f82448862910272e9f8168717b2c442f3d071ba9107ad7244a741ea9f4edd40c7815fd852234d5780a8ef8ab40b2c52f7da002610fc3e27c9735957595f8e07112ce92423daae19d09f5528c18775d7bba8a608638f3020fb075d55e8dee7987511713e45736bf278676feebf277a3c6fe2ae9e801181d3c53da617d07625416a678aeba7b126ab23e8958ba4ffa1a402f16cacbf3342fa749f06c27ec2656e6d66b4de054cbb64cbf961e24c6ac9e8f7c1407a565929f62bb50cccdc7757a7945faff754368ac61771918a54c179865c70b7b6d5c5814e1db518ef94782b6cb30305c4823a8cd4eaab0cbc3759
        self.q = q or 0x00bdb896139445a9c83238ff68bce7596733e15db37a1a98fc8bb789872939b24b
        self.g = g or 0x0b98ff89c7ad854caba5a164e956b18727489d0181d32a33f82623d15b9d42084e92086db9be27ddfbbe91feac716085d0823230e99d0b00a38ba2745d5cacc128f4ab9c153fc0dadc09962892eff544020e2859c9f4ba124489ce20a2fef3ed0677c651906e0718a2b3cdaee6bf9bdee6a2284ba60ac17dc97e245f436c1ead3dda342e2eb0c5db9756e6cfe3fe09dc331dca41f42b706cd935862f610834b3cf247a230451465f0d642350e53fa114a91ec82a2b8241bb37377ac35a3a686ff2bf94426ba60589de05e84189fb4a8e2e42fee3538994ceeed36ac3bbb86ffa46ca039fa6345d89112accfb7157e5aa9ea065db74fe4f45a820cc8f8ad05eb6

        self.x = x or Bytes.random((self.q.bit_length() + 7) // 8).int() % self.q
        self.y = pow(self.g, self.x, self.p)
        self.hash_obj = hash_obj



    def __repr__(self):
        return f"<DSA: hash_obj={self.hash_obj}, p={self.p}, q={self.q}, g={self.g}, x={self.x}, y={self.y}>"

    def __str__(self):
        return self.__repr__()



    def sign(self, message: bytes, k: int=None) -> (int, int):
        """
        Signs a `message`.

        Parameters:
            message (bytes): Message to sign.
            k         (int): (Optional) Ephemeral key.
        
        Returns:
            (int, int): Signature formatted as (r, s).
        """
        k = k or max(1, Bytes.random((self.q.bit_length() + 7) // 8).int() % self.q)
        inv_k = mod_inv(k, self.q)
        r = pow(self.g, k, self.p) % self.q
        s = (inv_k * (self.hash_obj.hash(message).int() + self.x * r)) % self.q
        return (r, s)



    def verify(self, message: bytes, sig: (int, int)) -> bool:
        """
        Verifies a `message` against a `sig`.

        Parameters:
            message  (bytes): Message.
            sig ((int, int)): Signature of `message`.
        
        Returns:
            bool: Whether the signature is valid or not.
        """
        (r, s) = sig
        w = mod_inv(s, self.q)
        u_1 = (self.hash_obj.hash(message).int() * w) % self.q
        u_2 = (r * w) % self.q
        v = (pow(self.g, u_1, self.p) * pow(self.y, u_2, self.p) % self.p) % self.q
        return v == r



    # Confirmed works on ECDSA as well
    def derive_k_from_sigs(self, msg_a: bytes, sig_a: (int, int), msg_b: bytes, sig_b: (int, int)) -> int:
        """
        Derives `k` from signatures that share an `r` value.

        Parameters:
            msg_a      (bytes): Message A.
            msg_b      (bytes): Message B.
            sig_a ((int, int)): Signature of `msg_a`.
            sig_b ((int, int)): Signature of `msg_b`.

        Returns:
            int: Derived `k`.
        """
        (r_a, s_a) = sig_a
        (r_b, s_b) = sig_b
        assert r_a == r_b

        s = (s_a - s_b) % self.q
        m = (self.hash_obj.hash(msg_a).int() - self.hash_obj.hash(msg_b).int()) % self.q
        return mod_inv(s, self.q) * m % self.q



    # Confirmed works on ECDSA as well
    def derive_x_from_k(self, message: bytes, k: int, sig: (int, int)) -> int:
        """
        Derives `x` from a known `k`.

        Parameters:
            message  (bytes): Message.
            k          (int): `k` used in `message`'s signature.
            sig ((int, int)): Signature of `message`.
        
        Returns:
            int: Derived `x`.
        """
        (r, s) = sig
        return ((s * k) - self.hash_obj.hash(message).int()) * mod_inv(r, self.q) % self.q
