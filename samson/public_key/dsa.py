from samson.math.general import mod_inv, find_prime, random_int_between, is_prime
from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import InvalidSignatureException

from samson.encoding.openssh.openssh_dsa_key import OpenSSHDSAPrivateKey, OpenSSHDSAPublicKey, SSH2DSAPublicKey
from samson.encoding.x509.x509_dsa_public_key import X509DSAPublicKey
from samson.encoding.pkcs1.pkcs1_dsa_private_key import PKCS1DSAPrivateKey
from samson.encoding.pkcs8.pkcs8_dsa_private_key import PKCS8DSAPrivateKey
from samson.encoding.x509.x509_dsa_certificate import X509DSACertificate, X509DSASigningAlgorithms, X509DSACertificateSigningRequest
from samson.encoding.general import PKIEncoding
from samson.core.encodable_pki import EncodablePKI
from samson.core.primitives import SignatureAlg, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive
from samson.hashes.sha2 import SHA256

@register_primitive()
class DSA(EncodablePKI, SignatureAlg):
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
        PKIEncoding.X509: X509DSAPublicKey,
        PKIEncoding.X509_CSR: X509DSACertificateSigningRequest
    }

    X509_SIGNING_ALGORITHMS = X509DSASigningAlgorithms
    X509_SIGNING_DEFAULT    = X509DSASigningAlgorithms.id_dsa_with_sha256

    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.KEY, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda dsa: dsa.q.bit_length()))
    USAGE_FREQUENCY = FrequencyType.OFTEN

    def __init__(self, hash_obj: object=SHA256(), p: int=None, q: int=None, g: int=None, x: int=None, L: int=2048, N: int=256):
        """
        Parameters:
            hash_obj (object): Instantiated object with compatible hash interface.
            p           (int): (Optional) Prime modulus.
            q           (int): (Optional) Prime modulus.
            g           (int): (Optional) Generator.
            x           (int): (Optional) Private key.
            L           (int): (Optional) Bit length of `p`.
            N           (int): (Optional) Bit length of `q`.
        """
        Primitive.__init__(self)
        # Parameter generation
        # https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
        if not q:
            q = find_prime(N)

            # Start somewhere in 2**(L-1); ensure it's even
            i = Bytes.random((L-1) // 8).int() // 2 * 2

            # Construct the base as an even multiple of `q`
            base = 2**(L-1) // (2*q) * 2
            while not is_prime((base + i) * q + 1):
                i += 2

            p = (base + i) * q + 1
            assert (p-1) % q == 0

            # Construct `g`
            while True:
                h = Bytes.random(N // 8).int() % (p-1)
                g = pow(h, (p-1) // q, p)

                if h > 1 and h < (p-1) and g > 1:
                    break

        self.p = p
        self.q = q
        self.g = g

        self.x = x or random_int_between(1, self.q)
        self.y = pow(self.g, self.x, self.p)
        self.hash_obj = hash_obj



    def __reprdir__(self):
        return ['hash_obj', 'p', 'q', 'g', 'x', 'y']



    def sign(self, message: bytes, k: int=None) -> (int, int):
        """
        Signs a `message`.

        Parameters:
            message (bytes): Message to sign.
            k         (int): (Optional) Ephemeral key.
        
        Returns:
            (int, int): Signature formatted as (r, s).
        """
        k = k or random_int_between(1, self.q)
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
        if r_a != r_b:
            raise ValueError('Signatures do not share an `r` value')

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
