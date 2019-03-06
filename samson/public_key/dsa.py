from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes

from samson.encoding.openssh.dsa_private_key import DSAPrivateKey
from samson.encoding.openssh.dsa_public_key import DSAPublicKey
from samson.encoding.openssh.general import generate_openssh_private_key, parse_openssh_key, generate_openssh_public_key_params
from samson.encoding.x509.x509_dsa_public_key import X509DSAPublicKey
from samson.encoding.pkcs1.pkcs1_dsa_private_key import PKCS1DSAPrivateKey
from samson.encoding.pkcs8.pkcs8_dsa_private_key import PKCS8DSAPrivateKey
from samson.encoding.x509.x509_dsa_certificate import X509DSACertificate
from samson.encoding.general import PKIEncoding

from samson.encoding.pem import pem_encode, pem_decode
from samson.hashes.sha2 import SHA256

SSH_PUBLIC_HEADER = b'ssh-dss'

class DSA(object):
    """
    Digital Signature Algorithm
    """

    def __init__(self, hash_obj: object=SHA256(), p: int=None, q: int=None, g: int=None, x: int=None):
        """
        Parameters:
            hash_obj (object): Instantiated object with compatible hash interface.
            p           (int): (Optional) Prime modulus.
            q           (int): (Optional) Prime modulus.
            g           (int): (Optional) Generator.
            x           (int): (Optional) Private key.
        """
        self.p = p or 0x800000000000000089E1855218A0E7DAC38136FFAFA72EDA7859F2171E25E65EAC698C1702578B07DC2A1076DA241C76C62D374D8389EA5AEFFD3226A0530CC565F3BF6B50929139EBEAC04F48C3C84AFB796D61E5A4F9A8FDA812AB59494232C7D2B4DEB50AA18EE9E132BFA85AC4374D7F9091ABC3D015EFC871A584471BB1
        self.q = q or 0xF4F47F05794B256174BBA6E9B396A7707E563C5B
        self.g = g or 0x5958C9D3898B224B12672C0B98E06C60DF923CB8BC999D119458FEF538B8FA4046C8DB53039DB620C094C9FA077EF389B5322A559946A71903F990F1F7E0E025E2D7F7CF494AFF1A0470F5B64C36B625A097F1651FE775323556FE00B3608C887892878480E99041BE601A62166CA6894BDD41A7054EC89F756BA9FC95302291

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



    @staticmethod
    def import_key(buffer: bytes, passphrase: bytes=None):
        """
        Builds an DSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffer     (bytes): DER and/or PEM-encoded bytes.
            passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
        
        Returns:
            DSA: DSA instance.
        """
        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer, passphrase)

        if SSH_PUBLIC_HEADER in buffer:
            priv, pub = parse_openssh_key(buffer, SSH_PUBLIC_HEADER, DSAPublicKey, DSAPrivateKey, passphrase)

            if priv:
                p, q, g, y, x = priv.p, priv.q, priv.g, priv.y, priv.x
            else:
                p, q, g, y, x = pub.p, pub.q, pub.g, pub.y, 0

            dsa = DSA(None, p=p, q=q, g=g, x=x)
            dsa.y = y

        else:
            if X509DSACertificate.check(buffer):
                dsa = X509DSACertificate.decode(buffer)
            
            elif PKCS8DSAPrivateKey.check(buffer):
                dsa = PKCS8DSAPrivateKey.decode(buffer)

            elif PKCS1DSAPrivateKey.check(buffer):
                dsa = PKCS1DSAPrivateKey.decode(buffer)

            elif X509DSAPublicKey.check(buffer):
                dsa = X509DSAPublicKey.decode(buffer)

            else:
                raise ValueError("Unable to parse provided DSA key.")

        return dsa



    def export_private_key(self, encode_pem: bool=True, encoding: PKIEncoding=PKIEncoding.PKCS1, marker: str=None, encryption: str=None, passphrase: bytes=None, iv: bytes=None) -> bytes:
        """
        Exports the full DSA instance into encoded bytes.

        Parameters:
            encode_pem      (bool): Whether or not to PEM-encode as well.
            encoding (PKIEncoding): Encoding scheme to use. Currently supports 'PKCS1', 'PKCS8', and 'OpenSSH'.
            marker           (str): Marker to use in PEM formatting (if applicable).
            encryption       (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
            passphrase     (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
            iv             (bytes): (Optional) IV to use for CBC encryption.

        Returns:
            bytes: Encoding of DSA instance.
        """
        if encoding == PKIEncoding.PKCS1:
            encoded = PKCS1DSAPrivateKey.encode(self)

            if encode_pem:
                encoded = pem_encode(encoded, marker or 'DSA PRIVATE KEY', encryption=encryption, passphrase=passphrase, iv=iv)

        elif encoding == PKIEncoding.PKCS8:
            encoded = PKCS8DSAPrivateKey.encode(self)

            if encode_pem:
                encoded = pem_encode(encoded, marker or 'PRIVATE KEY', encryption=encryption, passphrase=passphrase, iv=iv)

        elif encoding == PKIEncoding.OpenSSH:
            public_key = DSAPublicKey('public_key', self.p, self.q, self.g, self.y)
            private_key = DSAPrivateKey(
                'private_key',
                check_bytes=None,
                p=self.p,
                q=self.q,
                g=self.g,
                y=self.y,
                x=self.x,
                host=b'nohost@localhost'
            )

            encoded = generate_openssh_private_key(public_key, private_key, encode_pem, marker, encryption, iv, passphrase)
        else:
            raise ValueError(f'Unsupported encoding "{encoding}"')

        return encoded



    def export_public_key(self, encode_pem: bool=None, encoding: PKIEncoding=PKIEncoding.X509, marker: str=None) -> bytes:
        """
        Exports the only the public parameters of the DSA instance into encoded bytes.

        Parameters:
            encode_pem      (bool): Whether or not to PEM-encode as well.
            encoding (PKIEncoding): Encoding scheme to use. Currently supports 'X509', 'OpenSSH', and 'SSH2'.
            marker           (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: Encoding of DSA instance.
        """
        use_rfc_4716 = False

        if encoding == PKIEncoding.X509:
            encoded = X509DSAPublicKey.encode(self)
            default_marker = 'PUBLIC KEY'
            default_pem = True

        elif encoding in [PKIEncoding.OpenSSH, PKIEncoding.SSH2]:
            public_key = DSAPublicKey('public_key', self.p, self.q, self.g, self.y)
            encoded, default_pem, default_marker, use_rfc_4716 = generate_openssh_public_key_params(encoding, b'ssh-dss', public_key)
        else:
            raise ValueError(f'Unsupported encoding "{encoding}"')


        if (encode_pem is None and default_pem) or encode_pem:
            encoded = pem_encode(encoded, marker or default_marker, use_rfc_4716=use_rfc_4716)

        return encoded
