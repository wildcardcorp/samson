from fastecdsa.curve import P192, P224, P256, P384, P521
from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes
from samson.public_key.dsa import DSA
from samson.hashes.sha2 import SHA256
from samson.encoding.pem import pem_encode, pem_decode

from samson.encoding.openssh.ecdsa_private_key import ECDSAPrivateKey
from samson.encoding.openssh.ecdsa_public_key import ECDSAPublicKey
from samson.encoding.openssh.general import generate_openssh_private_key, parse_openssh_key, generate_openssh_public_key_params
from samson.encoding.jwk.jwk_ec_encoder import JWKECEncoder
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PKCS1ECDSAPrivateKey
from samson.encoding.pkcs8.pkcs8_ecdsa_private_key import PKCS8ECDSAPrivateKey
from samson.encoding.x509.x509_ecdsa_public_key import X509ECDSAPublicKey
from samson.encoding.x509.x509_ecdsa_certificate import X509ECDSACertificate
from samson.encoding.x509.x509_ecdsa_explicit_certificate import X509ECDSAExplicitCertificate
from samson.encoding.general import PKIEncoding

from fastecdsa.point import Point
import math


SSH_CURVE_NAME_LOOKUP = {
    P192: b'nistp192',
    P224: b'nistp224',
    P256: b'nistp256',
    P384: b'nistp384',
    P521: b'nistp521'
}

SSH_INVERSE_CURVE_LOOKUP = {v.decode():k for k, v in SSH_CURVE_NAME_LOOKUP.items()}

SSH_PUBLIC_HEADER = b'ecdsa-'

# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
class ECDSA(DSA):
    """
    Elliptical Curve Digital Signature Algorithm
    """

    def __init__(self, G: Point, hash_obj: object=SHA256(), d: int=None):
        """
        Parameters:
            G         (Point): Generator point for a curve.
            hash_obj (object): Instantiated object with compatible hash interface.
            d           (int): (Optional) Private key.
        """
        self.G = G
        self.q = self.G.curve.q
        self.d = d or max(1, Bytes.random(self.q.bit_length() + 7 // 8).int() % self.q)
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
            k = k or max(1, Bytes.random(self.q .bit_length() + 7 // 8).int() % self.q)
            inv_k = mod_inv(k, self.q)

            z = self.hash_obj.hash(message).int()
            z >>= max(self.hash_obj.digest_size * 8 - self.q.bit_length(), 0)

            r = (k * self.G).x % self.q
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


    # https://tools.ietf.org/html/rfc5656
    # https://github.com/golang/crypto/blob/master/ssh/keys.go
    # https://stackoverflow.com/questions/5929050/how-does-asn-1-encode-an-object-identifier
    @staticmethod
    def import_key(buffer: bytes, passphrase: bytes=None):
        """
        Builds an ECDSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffer     (bytes): DER and/or PEM-encoded bytes.
            passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
        
        Returns:
            ECDSA: ECDSA instance.
        """
        if JWKECEncoder.check(buffer):
            ecdsa = JWKECEncoder.decode(buffer)
        else:
            if buffer.startswith(b'----'):
                buffer = pem_decode(buffer, passphrase)

            if SSH_PUBLIC_HEADER in buffer:
                priv, pub = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, ECDSAPublicKey, ECDSAPrivateKey, passphrase)

                if priv:
                    curve, x_y_bytes, d = priv.curve, priv.x_y_bytes, priv.d
                else:
                    curve, x_y_bytes, d = pub.curve, pub.x_y_bytes, 1

                curve = SSH_INVERSE_CURVE_LOOKUP[curve.decode()]

                Q = Point(*ECDSA.decode_point(x_y_bytes), curve)
                ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
                ecdsa.Q = Q
            else:
                # if X509ECDSAExplicitCertificate.check(buffer):
                #     ecdsa = X509ECDSAExplicitCertificate.decode(buffer)

                if X509ECDSACertificate.check(buffer):
                    ecdsa = X509ECDSACertificate.decode(buffer)

                elif X509ECDSAPublicKey.check(buffer):
                    ecdsa = X509ECDSAPublicKey.decode(buffer)
                
                elif PKCS8ECDSAPrivateKey.check(buffer):
                    ecdsa = PKCS8ECDSAPrivateKey.decode(buffer)
                
                elif PKCS1ECDSAPrivateKey.check(buffer):
                    ecdsa = PKCS1ECDSAPrivateKey.decode(buffer)

                else:
                    raise ValueError("Unable to parse provided ECDSA key.")

        return ecdsa



    def format_public_point(self) -> str:
        """
        Internal function used for exporting the key. Formats `Q` into a bitstring.
        """
        zero_fill = math.ceil(self.G.curve.q.bit_length() / 8)
        pub_point_bs = bin((b'\x00\x04' + (Bytes(self.Q.x).zfill(zero_fill) + Bytes(self.Q.y).zfill(zero_fill))).int())[2:]
        pub_point_bs = pub_point_bs.zfill(math.ceil(len(pub_point_bs) / 8) * 8)
        return pub_point_bs



    def export_private_key(self, encode_pem: bool=True, encoding: PKIEncoding=PKIEncoding.PKCS1, marker: str=None, encryption: str=None, passphrase: bytes=None, iv: bytes=None) -> bytes:
        """
        Exports the full ECDSA instance into encoded bytes.

        Parameters:
            encode_pem      (bool): Whether or not to PEM-encode as well.
            encoding (PKIEncoding): Encoding scheme to use. Currently supports 'PKCS1', 'PKCS8', 'OpenSSH', and 'JWK'.
            marker           (str): Marker to use in PEM formatting (if applicable).
            encryption       (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
            passphrase     (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
            iv             (bytes): (Optional) IV to use for CBC encryption.
        
        Returns:
            bytes: Encoding of DSA instance.
        """
        zero_fill = math.ceil(self.G.curve.q.bit_length() / 8)

        if encoding == PKIEncoding.PKCS1:
            encoded = PKCS1ECDSAPrivateKey.encode(self)

            if encode_pem:
                encoded = pem_encode(encoded, marker or 'EC PRIVATE KEY', encryption=encryption, passphrase=passphrase, iv=iv)


        elif encoding == PKIEncoding.PKCS8:
            encoded = PKCS8ECDSAPrivateKey.encode(self)

            if encode_pem:
                encoded = pem_encode(encoded, marker or 'PRIVATE KEY', encryption=encryption, passphrase=passphrase, iv=iv)


        elif encoding == PKIEncoding.OpenSSH:
            curve = SSH_CURVE_NAME_LOOKUP[self.G.curve]
            x_y_bytes = b'\x04' + (Bytes(self.Q.x).zfill(zero_fill) + Bytes(self.Q.y).zfill(zero_fill))

            public_key = ECDSAPublicKey('public_key', curve, x_y_bytes)
            private_key = ECDSAPrivateKey(
                'private_key',
                check_bytes=None,
                curve=curve,
                x_y_bytes=x_y_bytes,
                d=self.d,
                host=b'nohost@localhost'
            )

            encoded = generate_openssh_private_key(public_key, private_key, encode_pem, marker, encryption, iv, passphrase)

        elif encoding == PKIEncoding.JWK:
            encoded = JWKECEncoder.encode(self, is_private=True).encode('utf-8')
        else:
            raise ValueError(f'Unsupported encoding "{encoding}"')

        return encoded



    def export_public_key(self, encode_pem: bool=None, encoding: PKIEncoding=PKIEncoding.X509, marker: str=None) -> bytes:
        """
        Exports the only the public parameters of the ECDSA instance into encoded bytes.

        Parameters:
            encode_pem      (bool): Whether or not to PEM-encode as well.
            encoding (PKIEncoding): Encoding scheme to use. Currently supports 'X509', 'OpenSSH', 'SSH2', and 'JWK'.
            marker           (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: Encoding of ECDSA instance.
        """
        zero_fill = math.ceil(self.G.curve.q.bit_length() / 8)
        curve = SSH_CURVE_NAME_LOOKUP[self.G.curve]
        x_y_bytes = b'\x04' + (Bytes(self.Q.x).zfill(zero_fill) + Bytes(self.Q.y).zfill(zero_fill))

        use_rfc_4716 = False
        

        if encoding == PKIEncoding.X509:
            encoded = X509ECDSAPublicKey.encode(self)

            default_marker = 'PUBLIC KEY'
            default_pem = True

        elif encoding in [PKIEncoding.OpenSSH, PKIEncoding.SSH2]:
            public_key = ECDSAPublicKey('public_key', curve, x_y_bytes)
            encoded, default_pem, default_marker, use_rfc_4716 = generate_openssh_public_key_params(encoding, b'ecdsa-sha2-' + curve, public_key)

        elif encoding == PKIEncoding.JWK:
            encoded = JWKECEncoder.encode(self, is_private=False).encode('utf-8')
            default_pem = False
        else:
            raise ValueError(f'Unsupported encoding "{encoding}"')


        if (encode_pem is None and default_pem) or encode_pem:
            encoded = pem_encode(encoded, marker or default_marker, use_rfc_4716=use_rfc_4716)

        return encoded
