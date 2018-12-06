from samson.utilities.math import gcd, lcm, mod_inv, find_prime
from samson.utilities.encoding import pem_encode, pem_decode
from samson.utilities.bytes import Bytes
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import Sequence, Integer
import random

class RSA(object):
    """
    Rivest-Shamir-Adleman public key cryptosystem
    """

    def __init__(self, bits: int, p: int=None, q: int=None, e: int=None):
        """
        Parameters:
            bits (int): Number of bits for strength and capacity.
            p (int): Secret prime modulus.
            q (int): Secret prime modulus.
            e (int): Public expoonent.
        """
        if p and q and not e:
            raise Exception("Argument 'e' must be set if 'p' and 'q' are set. ")

        self.e = e or 3
        phi = 0

        if p and q:
            phi = lcm(p - 1, q - 1)
            self.n = p * q

            if gcd(self.e, phi) != 1:
                raise Exception("Invalid 'p' and 'q': GCD(e, phi) != 1")
        else:
            next_p = p
            next_q = q
            while gcd(self.e, phi) != 1:
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

        self.phi = phi
        self.d = mod_inv(self.e, phi)
        self.alt_d = mod_inv(self.e, (self.p - 1) * (self.q - 1))

        self.pub = (self.e, self.n)
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
        plaintext = pow(ciphertext, self.d, self.n)
        return Bytes(plaintext, 'big')



    def export_key(self, encode_pem: bool=True) -> bytes:
        """
        Exports the RSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
        
        Returns:
            bytes: DER-encoding of RSA instance.
        """
        seq = Sequence()

        for x in [0, self.n, self.e, self.d, self.p, self.q]:
            seq.setComponentByPosition(len(seq), Integer(x))
        
        der_encoded = encoder.encode(seq)

        if encode_pem:
            der_encoded = pem_encode(der_encoded, 'RSA PRIVATE KEY')

        return der_encoded


    
    @staticmethod
    def import_key(buffer: bytes):
        """
        Builds an RSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffers (bytes): DER and/or PEM-encoded bytes.
        
        Returns:
            RSA: RSA instance.
        """
        try:
            buffer = pem_decode(buffer)
        except ValueError as _:
            pass
        

        seq = decoder.decode(buffer)
        _n, e, _d, p, q = [int(item) for item in seq[0][1:]]
        rsa = RSA(0, p=p, q=q, e=e)
        rsa.bits = rsa.n.bit_length()
        return rsa
    



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