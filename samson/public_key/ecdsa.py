from samson.math.general import mod_inv, random_int
from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve
from samson.utilities.bytes import Bytes
from samson.public_key.dsa import DSA
from samson.hashes.sha2 import SHA256

from samson.encoding.openssh.openssh_ecdsa_private_key import OpenSSHECDSAPrivateKey
from samson.encoding.openssh.openssh_ecdsa_public_key import OpenSSHECDSAPublicKey
from samson.encoding.openssh.ssh2_ecdsa_public_key import SSH2ECDSAPublicKey
from samson.encoding.jwk.jwk_ec_private_key import JWKECPrivateKey
from samson.encoding.jwk.jwk_ec_public_key import JWKECPublicKey
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PKCS1ECDSAPrivateKey
from samson.encoding.pkcs8.pkcs8_ecdsa_private_key import PKCS8ECDSAPrivateKey
from samson.encoding.x509.x509_ecdsa_public_key import X509ECDSAPublicKey
from samson.encoding.x509.x509_ecdsa_certificate import X509ECDSACertificate, X509ECDSASigningAlgorithms
from samson.encoding.general import PKIEncoding

import math

# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
class ECDSA(DSA):
    """
    Elliptical Curve Digital Signature Algorithm
    """

    PRIV_ENCODINGS = {
        PKIEncoding.JWK: JWKECPrivateKey,
        PKIEncoding.OpenSSH: OpenSSHECDSAPrivateKey,
        PKIEncoding.PKCS1: PKCS1ECDSAPrivateKey,
        PKIEncoding.PKCS8: PKCS8ECDSAPrivateKey
    }


    PUB_ENCODINGS = {
        PKIEncoding.JWK: JWKECPublicKey,
        PKIEncoding.OpenSSH: OpenSSHECDSAPublicKey,
        PKIEncoding.SSH2: SSH2ECDSAPublicKey,
        PKIEncoding.X509_CERT: X509ECDSACertificate,
        PKIEncoding.X509: X509ECDSAPublicKey
    }

    X509_SIGNING_ALGORITHMS = X509ECDSASigningAlgorithms
    X509_SIGNING_DEFAULT    = X509ECDSASigningAlgorithms.ecdsa_with_SHA256


    def __init__(self, G: WeierstrassCurve, hash_obj: object=SHA256(), d: int=None):
        """
        Parameters:
            G (WeierstrassCurve): Generator point for a curve.
            hash_obj    (object): Instantiated object with compatible hash interface.
            d              (int): (Optional) Private key.
        """
        self.G = G
        self.q = self.G.curve.q
        self.d = Bytes.wrap(d).int() if d else max(1, random_int(self.q))
        self.Q = self.d * self.G
        self.hash_obj = hash_obj


    def __repr__(self):
        return f"<ECDSA: d={self.d}, G={self.G}, Q={self.Q}, hash_obj={self.hash_obj}>"

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
        r = 0
        s = 0

        while s == 0 or r == 0:
            k = k or max(1, random_int(self.q))
            inv_k = mod_inv(k, self.q)

            z = self.hash_obj.hash(message).int()
            z >>= max(self.hash_obj.digest_size * 8 - self.q.bit_length(), 0)

            r = int((k * self.G).x) % self.q
            s = (inv_k * (z + self.d * r)) % self.q

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

        z = self.hash_obj.hash(message).int()
        z >>= max(self.hash_obj.digest_size * 8 - self.q.bit_length(), 0)

        u_1 = (z * w) % self.q
        u_2 = (r * w) % self.q
        v = u_1 * self.G + u_2 * self.Q
        return v.x == r


    @staticmethod
    def decode_point(x_y_bytes: bytes):
        x_y_bytes = Bytes.wrap(x_y_bytes)

        # Uncompressed Point
        if x_y_bytes[0] == 4:
            x_y_bytes = x_y_bytes[1:]
        else:
            raise NotImplementedError("Support for ECPoint decompression not implemented.")

        x, y = x_y_bytes[:len(x_y_bytes) // 2].int(), x_y_bytes[len(x_y_bytes) // 2:].int()
        return x, y


    def format_public_point(self) -> str:
        """
        Internal function used for exporting the key. Formats `Q` into a bitstring.
        """
        zero_fill = math.ceil(self.G.curve.q.bit_length() / 8)
        pub_point_bs = bin((b'\x00\x04' + (Bytes(int(self.Q.x)).zfill(zero_fill) + Bytes(int(self.Q.y)).zfill(zero_fill))).int())[2:]
        pub_point_bs = pub_point_bs.zfill(math.ceil(len(pub_point_bs) / 8) * 8)
        return pub_point_bs
