from samson.math.general import gcd, lcm, mod_inv, find_prime
from samson.core.encryption_alg import EncryptionAlg

from samson.encoding.openssh.openssh_rsa_private_key import OpenSSHRSAPrivateKey
from samson.encoding.openssh.openssh_rsa_public_key import OpenSSHRSAPublicKey
from samson.encoding.openssh.ssh2_rsa_public_key import SSH2RSAPublicKey
from samson.encoding.jwk.jwk_rsa_public_key import JWKRSAPublicKey
from samson.encoding.jwk.jwk_rsa_private_key import JWKRSAPrivateKey
from samson.encoding.pkcs1.pkcs1_rsa_private_key import PKCS1RSAPrivateKey
from samson.encoding.pkcs8.pkcs8_rsa_private_key import PKCS8RSAPrivateKey
from samson.encoding.pkcs1.pkcs1_rsa_public_key import PKCS1RSAPublicKey
from samson.encoding.x509.x509_rsa_certificate import X509RSACertificate, X509RSASigningAlgorithms
from samson.encoding.x509.x509_rsa_public_key import X509RSAPublicKey
from samson.encoding.general import PKIEncoding

from samson.utilities.bytes import Bytes
from samson.core.encodable_pki import EncodablePKI
import random

from samson.ace.decorators import creates_constraint
from samson.ace.constraints import RSAConstraint

@creates_constraint(RSAConstraint())
class RSA(EncryptionAlg, EncodablePKI):
    """
    Rivest-Shamir-Adleman public key cryptosystem
    """

    PRIV_ENCODINGS = {
        PKIEncoding.JWK: JWKRSAPrivateKey,
        PKIEncoding.OpenSSH: OpenSSHRSAPrivateKey,
        PKIEncoding.PKCS1: PKCS1RSAPrivateKey,
        PKIEncoding.PKCS8: PKCS8RSAPrivateKey
    }


    PUB_ENCODINGS = {
        PKIEncoding.JWK: JWKRSAPublicKey,
        PKIEncoding.OpenSSH: OpenSSHRSAPublicKey,
        PKIEncoding.SSH2: SSH2RSAPublicKey,
        PKIEncoding.X509_CERT: X509RSACertificate,
        PKIEncoding.X509: X509RSAPublicKey,
        PKIEncoding.PKCS1: PKCS1RSAPublicKey
    }

    X509_SIGNING_ALGORITHMS = X509RSASigningAlgorithms
    X509_SIGNING_DEFAULT    = X509RSASigningAlgorithms.sha256WithRSAEncryption

    def __init__(self, bits: int, p: int=None, q: int=None, e: int=65537):
        """
        Parameters:
            bits (int): Number of bits for strength and capacity.
            p    (int): Secret prime modulus.
            q    (int): Secret prime modulus.
            e    (int): Public exponent.
        """
        self.e = e
        phi = 0

        if p and q:
            phi = lcm(p - 1, q - 1)
            self.n = p * q

            if gcd(self.e, phi) != 1:
                raise Exception("Invalid 'p' and 'q': GCD(e, phi) != 1")

            bits = p.bit_length() + q.bit_length()
        else:
            next_p = p
            next_q = q
            while gcd(self.e, phi) != 1 or next_p == next_q:
                if not p:
                    next_p = find_prime(bits // 2)

                if not q:
                    next_q = find_prime(bits // 2)

                phi = lcm(next_p - 1, next_q - 1)

            p = next_p
            q = next_q
            self.n = p * q

        self.p = p
        self.q = q

        self.bits = bits

        self.phi   = phi
        self.d     = mod_inv(self.e, phi)
        self.alt_d = mod_inv(self.e, (self.p - 1) * (self.q - 1))

        self.dP = self.d % (self.p-1)
        self.dQ = self.d % (self.q-1)
        self.Qi = mod_inv(self.q, self.p)

        self.pub  = (self.e, self.n)
        self.priv = (self.d, self.n)



    def __repr__(self):
        return f"<RSA: bits={self.bits}, p={self.p}, q={self.q}, e={self.e}, n={self.n}, phi={self.phi}, d={self.d}, alt_d={self.alt_d}>"

    def __str__(self):
        return self.__repr__()



    def encrypt(self, plaintext: bytes) -> int:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Plaintext.
        
        Returns:
            int: Ciphertext.
        """
        m = Bytes.wrap(plaintext).int()
        return pow(m, self.e, self.n)



    def decrypt(self, ciphertext: int) -> Bytes:
        """
        Decrypts `ciphertext` back into plaintext.

        Parameters:
            ciphertext (int): Ciphertext.
        
        Returns:
            Bytes: Decrypted plaintext.
        """
        plaintext = pow(Bytes.wrap(ciphertext).int(), self.d, self.n)
        return Bytes(plaintext, 'big')



    @staticmethod
    def factorize_from_shared_p(n1: int, n2: int, e: int):
        """
        Factorizes the moduli of two instances that share a common secret prime. See `Batch GCD`.

        Parameters:
            n1 (int): Modulus of the first instance.
            n2 (int): Modulus of the second instance.
            e  (int): Public exponent.
        
        Returns:
            (RSA, RSA): Both cracked RSA instances.
        """
        assert n1 != n2

        # Find shared `p`
        p = gcd(n1, n2)

        q1 = n1 // p
        q2 = n2 // p

        return (RSA(0, p=p, q=q1, e=e), RSA(0, p=p, q=q2, e=e))


    @staticmethod
    def factorize_from_faulty_crt(message: int, faulty_sig: int, e: int, n: int):
        """
        Factorize the secret primes from a faulty signature produced with CRT-optimized RSA.

        Parameters:
            message    (int): Message.
            faulty_sig (int): Faulty signature of `message`.
            e          (int): Public exponent.
            n          (int): Modulus.
        
        Returns:
            RSA: Cracked RSA instance.
        """
        q = gcd(pow(faulty_sig, e, n) - message, n)
        p = n // q

        return RSA(0, p=p, q=q, e=e)


    @staticmethod
    def factorize_from_d(d: int, e: int, n: int):
        """
        Factorizes the secret primes from the private key `d`.

        Parameters:
            d (int): Private key.
            e (int): Public exponent.
            n (int): Modulus.
        
        Returns:
            RSA: Full RSA instance.
        """
        k = d*e - 1
        p = None
        q = None

        while not p:
            g = random.randint(2, n - 1)
            t = k

            while t % 2 == 0:
                t = t // 2
                x = pow(g, t, n)

                if x > 1 and gcd(x - 1, n) > 1:
                    p = gcd(x - 1, n)
                    q = n // p
                    break

        return RSA(0, p=p, q=q, e=e)
