from samson.math.general import gcd, lcm, mod_inv, find_prime

from samson.encoding.openssh.openssh_rsa_key import OpenSSHRSAPrivateKey, OpenSSHRSAPublicKey, SSH2RSAPublicKey
from samson.encoding.jwk.jwk_rsa_public_key import JWKRSAPublicKey
from samson.encoding.jwk.jwk_rsa_private_key import JWKRSAPrivateKey
from samson.encoding.pkcs1.pkcs1_rsa_private_key import PKCS1RSAPrivateKey
from samson.encoding.pkcs8.pkcs8_rsa_private_key import PKCS8RSAPrivateKey
from samson.encoding.pkcs1.pkcs1_rsa_public_key import PKCS1RSAPublicKey
from samson.encoding.x509.x509_rsa_certificate import X509RSACertificate, X509RSASigningAlgorithms, X509RSACertificateSigningRequest
from samson.encoding.x509.x509_rsa_public_key import X509RSAPublicKey
from samson.encoding.dns_key.dns_key_rsa_key import DNSKeyRSAPublicKey, DNSKeyRSAPrivateKey
from samson.encoding.general import PKIEncoding

from samson.utilities.exceptions import NoSolutionException
from samson.utilities.bytes import Bytes
from samson.core.encodable_pki import EncodablePKI
from samson.core.primitives import Primitive, NumberTheoreticalAlg
from samson.core.metadata import SecurityProofType, FrequencyType
from samson.ace.decorators import creates_constraint, register_primitive
from samson.ace.constraints import RSAConstraint

@creates_constraint(RSAConstraint())
@register_primitive()
class RSA(NumberTheoreticalAlg, EncodablePKI):
    """
    Rivest-Shamir-Adleman public key cryptosystem
    """

    PRIV_ENCODINGS = {
        PKIEncoding.JWK: JWKRSAPrivateKey,
        PKIEncoding.OpenSSH: OpenSSHRSAPrivateKey,
        PKIEncoding.PKCS1: PKCS1RSAPrivateKey,
        PKIEncoding.PKCS8: PKCS8RSAPrivateKey,
        PKIEncoding.DNS_KEY: DNSKeyRSAPrivateKey
    }


    PUB_ENCODINGS = {
        PKIEncoding.JWK: JWKRSAPublicKey,
        PKIEncoding.OpenSSH: OpenSSHRSAPublicKey,
        PKIEncoding.SSH2: SSH2RSAPublicKey,
        PKIEncoding.X509_CERT: X509RSACertificate,
        PKIEncoding.X509: X509RSAPublicKey,
        PKIEncoding.PKCS1: PKCS1RSAPublicKey,
        PKIEncoding.DNS_KEY: DNSKeyRSAPublicKey,
        PKIEncoding.X509_CSR: X509RSACertificateSigningRequest
    }

    X509_SIGNING_ALGORITHMS = X509RSASigningAlgorithms
    X509_SIGNING_DEFAULT    = X509RSASigningAlgorithms.sha256WithRSAEncryption

    SECURITY_PROOF  = SecurityProofType.INTEGER_FACTORIZATION
    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, bits: int=None, p: int=None, q: int=None, e: int=65537, n :int=None):
        """
        Parameters:
            bits (int): Number of bits for strength and capacity.
            p    (int): Secret prime modulus.
            q    (int): Secret prime modulus.
            e    (int): Public exponent.
            n    (int): Public modulus.
        """
        Primitive.__init__(self)

        self.e = e
        phi = 0

        if p and q:
            phi = lcm(p - 1, q - 1)
            self.n = p * q

            if gcd(self.e, phi) != 1:
                raise ValueError("Invalid 'p' and 'q': GCD(e, phi) != 1")

            bits = self.n.bit_length()

        elif n:
            self.n = n

        else:
            next_p = p
            next_q = q

            # Take into account the bits needed to complete `bits` if `p` or `q` are already defined
            if p:
                q_bits = bits - p.bit_length()
            else:
                q_bits = bits // 2

            if q:
                p_bits = bits - q.bit_length()
            else:
                p_bits = bits // 2


            # Find the primes
            while gcd(self.e, phi) != 1 or next_p == next_q:
                if not p:
                    next_p = find_prime(p_bits)

                if not q:
                    next_q = find_prime(q_bits)

                phi = lcm(next_p - 1, next_q - 1)

            p = next_p
            q = next_q
            self.n = p * q

        self.p   = p
        self.q   = q
        self.phi = phi

        self.bits = bits or n.bit_length()

        if self.p and self.q:
            self.d     = mod_inv(self.e, phi)
            self.alt_d = mod_inv(self.e, (self.p - 1) * (self.q - 1))

            self.dP = self.d % (self.p-1)
            self.dQ = self.d % (self.q-1)
            self.Qi = mod_inv(self.q, self.p)
        else:
            self.d     = None
            self.alt_d = None

        self.pub  = (self.e, self.n)
        self.priv = (self.d, self.n)



    def __reprdir__(self):
        return ['bits', 'e', 'd', 'alt_d', 'p', 'q', 'n', 'phi']


    def __eq__(self, other):
        if self.__class__ != other.__class__:
            return False

        s_dict, o_dict = self.__dict__, other.__dict__

        for key in s_dict:
            if key in ['p', 'q']:
                if s_dict[key] not in [o_dict['p'], o_dict['q']]:
                    return False
            else:
                if s_dict[key] != o_dict[key]:
                    return False

        return True


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
        import random

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



    @staticmethod
    def check_roca(n: int) -> bool:
        """
        Determines whether `n` is vulnerable to Return of Coppersmith's Attack ("ROCA", CVE-2017-15361).

        Parameters:
            n (int): Modulus to test.
        
        Returns:
            bool: Whether or not `n` is vulnerable.
        """
        from samson.auxiliary.roca import check_roca
        return check_roca(n)



    @staticmethod
    def franklin_reiter(n: int, e:int, c1: bytes, c2: bytes, a: int, b: int) -> (Bytes, Bytes):
        """
        Plaintext recovery attack on related messages. If two messages `m1` and `m2` are encrypted under
        the same RSA key and differ by a polynomial `f`(`x`)=`a``x`+`b` such that `f`(`m2`)=`m1`,
        an attacker can recover both messages.

        Parameters:
            n    (int): Modulus.
            e    (int): Public exponent.
            c1 (bytes): First ciphertext.
            c2 (bytes): Second ciphertext.
            a    (int): Degree one coefficient of `f`.
            b    (int): Degree zero coefficient of `f`.

        Returns:
            (Bytes, Bytes): Formatted as (plaintext of `c1`, plaintext of `c2`).

        Examples:
            >>> from samson.public_key.rsa import RSA
            >>> from samson.utilities.bytes import Bytes
            >>> n = 12888116222751572707240304314061489969911517689681896002815278735734599554528139201175828301306206875758015813657671194091088574408652687049044678022350881
            >>> e = 3
            >>> c1, c2 = (1069840764750984151382541524182133076049036437301406613777333377072807719543492846608433094574284616519736184031434837790828328968169604334545475452353520, 6128850605905061316574224955190498492830401383027566668909504849309619877251329707299254116186505675740734972894129266563268585885907678840482692103494952)
            >>> msg_1, msg_2 = (4522760776158455690156842391692112439215231484566493313552482744592035149379214992316932614241610059456557632128387082728369044265, 4522760776158455690156842391692112439215123068100955980064492871261939142436073092871197229985928362464740136774601007644199107151)
            >>> RSA.franklin_reiter(n, e, c1, c2, 1, -(msg_2 - msg_1)) == (Bytes(msg_1), Bytes(msg_2))
            True

        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.symbols import Symbol
        x = Symbol('x')

        c1, c2  = [Bytes.wrap(item).int() for item in [c1, c2]]

        Zn = ZZ/ZZ(n)
        _  = Zn[x]

        f = a*x + b
        f = f.monic()

        g1 = f**e - c1
        g2 = x**e - c2

        g3 = g1.gcd(g2, use_naive=True)

        if g3.degree() != 1:
            raise NoSolutionException(f"Resultant polynomial ({g3}) is not degree one")

        m2 = int(-g3[0])
        return Bytes(int(f(m2))), Bytes(m2)


    @staticmethod
    def duplicate_ciphertext_key_selection(n: int, plaintext: bytes, ciphertext: bytes, max_glue_size: int=20) -> 'RSA':
        """
        Generates an `RSA` key of size greater than `n` such that `ciphertext` decrypts to `plaintext`.

        Parameters:
            n             (int): Target RSA modulus.
            plaintext   (bytes): Plaintext to decrypt to.
            ciphertext  (bytes): Target ciphertext.
            max_glue_size (int): Maximum bit size of prime divisors of `p-1` and `q-1`. Used internally.

        Returns:
            RSA: RSA key that decrypts `ciphertext` to `plaintext`.

        Examples:
            >>> from samson.public_key.rsa import RSA
            >>> rsa = RSA(256)
            >>> ct  = rsa.encrypt(b'mymsg')
            >>> dup = RSA.duplicate_ciphertext_key_selection(rsa.n, b'malicious', ct)
            >>> dup.decrypt(ct)
            <Bytes: b'malicious', byteorder='big'>

        References:
            https://toadstyle.org/cryptopals/61.txt
        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.general import pohlig_hellman, crt, next_prime, kth_root
        from samson.math.prime_gen import PrimeEngine
        from samson.math.factorization.general import factor
        from samson.utilities.exceptions import SearchspaceExhaustedException

        pt   = Bytes.wrap(plaintext).int()
        ct   = Bytes.wrap(ciphertext).int()
        bits = n.bit_length()
        prime_size = (bits+1) // 2

        def find_e_residue(p, m, s):
            Zp  = ZZ/ZZ(p)
            Zps = Zp.mul_group()
            return pohlig_hellman(Zps(s), Zps(m))


        def has_res(p):
            try:
                find_e_residue(p, pt, ct)
                return True
            except SearchspaceExhaustedException:
                return False


        # By ensuring both primes are greater than sqrt(n), we guarantee our modulus
        # will be larger and thus large enough for the plaintext.
        sqrt = kth_root(n, 2)
        def is_greater(p):
            return p > sqrt


        # `pt` and `ct` must be in the same subgroup, so we'll just ensure they're
        # primitive roots
        constraints = [
            PrimeEngine.CONSTRAINTS.HAS_PRIMITIVE_ROOT(pt),
            PrimeEngine.CONSTRAINTS.HAS_PRIMITIVE_ROOT(ct),
            has_res,
            is_greater
        ]

        p_base = 3
        while not pt % p_base or not ct % p_base:
            p_base = next_prime(p_base+1)

        # Generate smooth `p`
        p = PrimeEngine.GENS.SMOOTH(prime_size, base=p_base, max_glue_size=max_glue_size).generate(constraints)

        # Make sure `q` shares no factors with p except 2
        p_1_facs = factor(p-1)
        q_base   = p_base
        while q_base in p_1_facs or not pt % q_base or not ct % q_base:
            q_base = next_prime(q_base+1)


        q = PrimeEngine.GENS.SMOOTH(prime_size, base=q_base, max_glue_size=max_glue_size, glue_prime_exclude=set(p_1_facs)).generate(constraints)


        # Craft `e`
        ep = find_e_residue(p, ct, pt)
        eq = find_e_residue(q, ct, pt)

        e_prime = crt([(ep, (p-1)//2), (eq, q-1)])[0]
        return RSA(p=p, q=q, e=e_prime)



    @staticmethod
    def wieners_attack(n: int, e: int) -> int:
        """
        Key recovery attack that uses `n` as an approximation of `phi` when `d` < 1/3 * `N`^(1/4).

        Parameters:
            n (int): Modulus.
            e (int): Public exponent.

        Returns:
            RSA: Recovered private key.

        Examples:
            >>> # Set up Wiener's Attack
            >>> rsa = RSA(256)
            >>> d   = random_int_between(3, kth_root(rsa.n, 4) // 3)
            >>> d   = next_prime(d)
            >>> rsa = RSA(p=rsa.p, q=rsa.q, e=mod_inv(d, (rsa.p-1) * (rsa.q-1)))
            >>> #
            >>> # Recover and prove correctness
            >>> recovered = RSA.wieners_attack(rsa.n, rsa.e)
            >>> message   = Bytes.random(7)
            >>> recovered.decrypt(rsa.encrypt(message)) == message
            True

        References:
            https://en.wikipedia.org/wiki/Wiener%27s_attack
        """
        from samson.math.all import QQ
        from samson.math.continued_fraction import ContinuedFraction

        m  = pow(2, e, n)
        cf = ContinuedFraction(QQ((e, n)))

        for denom in cf.denominators():
            if pow(m, int(denom), n) == 2:
                return RSA.factorize_from_d(int(denom), e, n)
