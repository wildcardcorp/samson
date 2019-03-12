from samson.utilities.bytes import Bytes
from samson.public_key.dsa import DSA
from samson.utilities.ecc import EdwardsCurve25519, TwistedEdwardsPoint, TwistedEdwardsCurve, bit
from samson.hashes.sha2 import SHA512
from samson.encoding.pem import pem_decode, pem_encode

from samson.encoding.openssh.openssh_eddsa_private_key import OpenSSHEdDSAPrivateKey
from samson.encoding.openssh.openssh_eddsa_public_key import OpenSSHEdDSAPublicKey
from samson.encoding.openssh.ssh2_eddsa_public_key import SSH2EdDSAPublicKey
from samson.encoding.pkcs8.pkcs8_eddsa_private_key import PKCS8EdDSAPrivateKey
from samson.encoding.x509.x509_eddsa_public_key import X509EdDSAPublicKey
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
        PKIEncoding.PKCS8: PKCS8EdDSAPrivateKey
    }


    PUB_ENCODINGS = {
        PKIEncoding.OpenSSH: OpenSSHEdDSAPublicKey,
        PKIEncoding.SSH2: SSH2EdDSAPublicKey,
        PKIEncoding.X509: X509EdDSAPublicKey
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
        x, y = P.x, P.y
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
        x = self.curve.recover_point_from_y(y).x

        if (x & 1) != bit(in_bytes, self.curve.b-1):
            x = self.curve.q - x

        return TwistedEdwardsPoint(x, y, self.curve)



    def sign(self, message: bytes) -> (int, int):
        """
        Signs a `message`.

        Parameters:
            message (bytes): Message to sign.
            k         (int): (Optional) Ephemeral key.
        
        Returns:
            (int, int): Signature formatted as (r, s).
        """
        r = self.H.hash(self.curve.magic + self.h[self.curve.b//8:] + message)[::-1].int()
        R = self.B * (r % self.curve.l)
        eR = self.encode_point(R)
        k = self.H.hash(self.curve.magic + eR + self.encode_point(self.A) + message)[::-1].int()
        S = (r + (k % self.curve.l) * self.a) % self.curve.l
        return eR + Bytes(S, 'little').zfill(self.curve.b//8)



    def verify(self, message: bytes, sig: (int, int)) -> bool:
        """
        Verifies a `message` against a `sig`.

        Parameters:
            message  (bytes): Message.
            sig ((int, int)): Signature of `message`.
        
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



    # @staticmethod
    # def import_key(buffer: bytes, passphrase: bytes=None):
    #     """
    #     Builds an EdDSA instance from DER and/or PEM-encoded bytes.

    #     Parameters:
    #         buffer     (bytes): DER and/or PEM-encoded bytes.
    #         passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
        
    #     Returns:
    #         EdDSA: EdDSA instance.
    #     """
    #     if buffer.startswith(b'----'):
    #         buffer = pem_decode(buffer, passphrase)

    #     if OpenSSHEdDSAPrivateKey.check(buffer, passphrase):
    #         eddsa = OpenSSHEdDSAPrivateKey.decode(buffer, passphrase)

    #     elif OpenSSHEdDSAPublicKey.check(buffer):
    #         eddsa = OpenSSHEdDSAPublicKey.decode(buffer)

    #     elif SSH2EdDSAPublicKey.check(buffer):
    #         eddsa = SSH2EdDSAPublicKey.decode(buffer)

    #     elif PKCS8EdDSAPrivateKey.check(buffer):
    #         eddsa = PKCS8EdDSAPrivateKey.decode(buffer)

    #     elif X509EdDSAPublicKey.check(buffer):
    #         eddsa = X509EdDSAPublicKey.decode(buffer)

    #     else:
    #         raise ValueError("Unable to parse provided EdDSA key.")

    #     return eddsa


    # def export_private_key(self, encode_pem: bool=True, encoding: PKIEncoding=PKIEncoding.OpenSSH, marker: str=None, encryption: str=None, passphrase: bytes=None, iv: bytes=None) -> bytes:
    #     """
    #     Exports the full EdDSA instance into encoded bytes.

    #     Parameters:
    #         encode_pem      (bool): Whether or not to PEM-encode as well.
    #         encoding (PKIEncoding): Encoding scheme to use. Currently supports 'OpenSSH'.
    #         marker           (str): Marker to use in PEM formatting (if applicable).
    #         encryption       (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
    #         passphrase     (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
    #         iv             (bytes): (Optional) IV to use for CBC encryption.
        
    #     Returns:
    #         bytes: Bytes-encoded EdDSA instance.
    #     """
    #     if encoding == PKIEncoding.OpenSSH:
    #         encoded = OpenSSHEdDSAPrivateKey.encode(self, encode_pem, marker, encryption, iv, passphrase)

    #     elif encoding == PKIEncoding.PKCS8:
    #         encoded = PKCS8EdDSAPrivateKey.encode(self)

    #         if encode_pem:
    #             encoded = pem_encode(encoded, marker or PKCS8EdDSAPrivateKey.DEFAULT_MARKER, encryption=encryption, passphrase=passphrase, iv=iv)

    #     else:
    #         raise ValueError(f'Unsupported encoding "{encoding}"')

    #     return encoded


    # def export_public_key(self, encode_pem: bool=None, encoding: PKIEncoding=PKIEncoding.OpenSSH, marker: str=None) -> bytes:
    #     """
    #     Exports the only the public parameters of the EdDSA instance into encoded bytes.

    #     Parameters:
    #         encode_pem      (bool): Whether or not to PEM-encode as well.
    #         encoding (PKIEncoding): Encoding scheme to use. Currently supports 'OpenSSH', and 'SSH2'.
    #         marker           (str): Marker to use in PEM formatting (if applicable).
        
    #     Returns:
    #         bytes: Encoding of EdDSA instance.
    #     """
    #     use_rfc_4716 = False

    #     if encoding == PKIEncoding.X509:
    #         encoded = X509EdDSAPublicKey.encode(self)
    #         default_marker = X509EdDSAPublicKey.DEFAULT_MARKER
    #         default_pem = X509EdDSAPublicKey.DEFAULT_PEM

    #     elif encoding == PKIEncoding.OpenSSH:
    #         encoded = OpenSSHEdDSAPublicKey.encode(self)
    #         default_marker = OpenSSHEdDSAPublicKey.DEFAULT_MARKER
    #         default_pem = OpenSSHEdDSAPublicKey.DEFAULT_PEM

    #     elif encoding == PKIEncoding.SSH2:
    #         encoded = SSH2EdDSAPublicKey.encode(self)
    #         default_marker = SSH2EdDSAPublicKey.DEFAULT_MARKER
    #         default_pem = SSH2EdDSAPublicKey.DEFAULT_PEM
    #         use_rfc_4716 = SSH2EdDSAPublicKey.USE_RFC_4716

    #     else:
    #         raise ValueError(f'Unsupported encoding "{encoding}"')


    #     if (encode_pem is None and default_pem) or encode_pem:
    #         encoded = pem_encode(encoded, marker or default_marker, use_rfc_4716=use_rfc_4716)

    #     return encoded
