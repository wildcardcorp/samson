from samson.utilities.bytes import Bytes
from samson.public_key.dsa import DSA
from samson.math.algebra.curves.twisted_edwards_curve import TwistedEdwardsPoint, TwistedEdwardsCurve, bit
from samson.math.algebra.curves.named import EdwardsCurve25519
from samson.hashes.sha2 import SHA512

from samson.encoding.openssh.openssh_eddsa_private_key import OpenSSHEdDSAPrivateKey
from samson.encoding.openssh.openssh_eddsa_public_key import OpenSSHEdDSAPublicKey
from samson.encoding.openssh.ssh2_eddsa_public_key import SSH2EdDSAPublicKey
from samson.encoding.pkcs8.pkcs8_eddsa_private_key import PKCS8EdDSAPrivateKey
from samson.encoding.x509.x509_eddsa_public_key import X509EdDSAPublicKey
from samson.encoding.jwk.jwk_eddsa_private_key import JWKEdDSAPrivateKey
from samson.encoding.jwk.jwk_eddsa_public_key import JWKEdDSAPublicKey
from samson.encoding.general import PKIEncoding

# Originally (reverse?)-engineered from: https://ed25519.cr.yp.to/python/ed25519.py
# Fit to RFC8032 (https://tools.ietf.org/html/rfc8032#appendix-A)
# and against OpenSSH_7.8p1
class EdDSA(DSA):
    """
    Edwards Curve Digitial Signature Algorithm
    """

    PRIV_ENCODINGS = {
        PKIEncoding.OpenSSH: OpenSSHEdDSAPrivateKey,
        PKIEncoding.PKCS8: PKCS8EdDSAPrivateKey,
        PKIEncoding.JWK: JWKEdDSAPrivateKey
    }


    PUB_ENCODINGS = {
        PKIEncoding.OpenSSH: OpenSSHEdDSAPublicKey,
        PKIEncoding.SSH2: SSH2EdDSAPublicKey,
        PKIEncoding.X509: X509EdDSAPublicKey,
        PKIEncoding.JWK: JWKEdDSAPublicKey
    }

    def __init__(self, curve: TwistedEdwardsCurve=EdwardsCurve25519, hash_obj: object=SHA512(), d: int=None, A: TwistedEdwardsPoint=None, a: int=None, h: bytes=None, clamp: bool=True):
        """
        Parameters:
            curve (TwistedEdwardsCurve): Curve used for calculations.
            hash_obj           (object): Instantiated object with compatible hash interface.
            d                     (int): Private key.
            A     (TwistedEdwardsPoint): (Optional) Public point.
            a                     (int): (Optional) Public scalar.
            h                   (bytes): (Optional) Hashed private key.
            clamp                (bool): Whether or not to clamp the public scalar.
        """
        self.B = curve.B
        self.curve = curve
        self.d = Bytes.wrap(d or max(1, Bytes.random(hash_obj.digest_size).int()))
        self.H = hash_obj

        self.h = h or hash_obj.hash(self.d)

        a = a or self.h[:self.curve.b // 8].int()
        self.a = curve.clamp_to_curve(a, True) if clamp else a

        self.A = A or self.B * self.a



    def __repr__(self):
        return f"<EdDSA: d={self.d}, a={self.a}, A={self.A}, curve={self.curve}, H={self.H}>"

    def __str__(self):
        return self.__repr__()


    def encode_point(self, P: TwistedEdwardsPoint) -> Bytes:
        """
        Encodes a `TwistedEdwardsPoint` as `Bytes`.

        Parameters:
            P (TwistedEdwardsPoint): Point to encode.
        
        Returns:
            Bytes: `Bytes` encoding.
        """
        x, y = int(P.x), int(P.y)
        return Bytes(((x & 1) << self.curve.b-1) + ((y << 1) >> 1), 'little').zfill(self.curve.b // 8)



    def decode_point(self, in_bytes: Bytes) -> TwistedEdwardsPoint:
        """
        Decodes `Bytes` to a `TwistedEdwardsPoint`.

        Parameters:
            in_bytes (Bytes): `TwistedEdwardsPoint` encoded as `Bytes`.
        
        Returns:
            TwistedEdwardsPoint: Decoded point.
        """
        y_bytes = Bytes([_ for _ in in_bytes], 'little')
        y_bytes[-1] &= 0x7F
        y = y_bytes.int()
        x = int(self.curve.recover_point_from_y(y).x)

        if (x & 1) != bit(in_bytes, self.curve.b-1):
            x = self.curve.q - x

        return TwistedEdwardsPoint(x, y, self.curve)



    def get_pub_bytes(self) -> Bytes:
        return self.encode_point(self.A)



    def sign(self, message: bytes) -> Bytes:
        """
        Signs a `message`.

        Parameters:
            message (bytes): Message to sign.
            k         (int): (Optional) Ephemeral key.
        
        Returns:
            Bytes: Signature formatted as r + s.
        """
        r  = self.H.hash(self.curve.magic + self.h[self.curve.b//8:] + message)[::-1].int()
        R  = self.B * (r % self.curve.l)
        eR = self.encode_point(R)
        k  = self.H.hash(self.curve.magic + eR + self.encode_point(self.A) + message)[::-1].int()
        S  = (r + (k % self.curve.l) * self.a) % self.curve.l
        return eR + Bytes(S, 'little').zfill(self.curve.b//8)



    def verify(self, message: bytes, sig: bytes) -> bool:
        """
        Verifies a `message` against a `sig`.

        Parameters:
            message (bytes): Message.
            sig     (bytes): Signature of `message`.
        
        Returns:
            bool: Whether the signature is valid or not.
        """
        sig = Bytes.wrap(sig, 'little')

        if len(sig) != self.curve.b // 4:
            raise ValueError("`sig` length is wrong.")

        R = self.decode_point(sig[:self.curve.b//8])
        S = sig[self.curve.b//8:].int()

        h = self.H.hash(self.curve.magic + self.encode_point(R) + self.encode_point(self.A) + message)[::-1].int()

        return self.B * S == R + (self.A * h)
