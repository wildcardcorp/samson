from samson.utilities.math import gcd, lcm, mod_inv, find_prime
from samson.utilities.encoding import export_der, bytes_to_der_sequence
from samson.utilities.bytes import Bytes
from pyasn1.codec.der import decoder
from pyasn1.type.univ import BitString
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



    def export_private_key(self, encode_pem: bool=True, marker: str='RSA PRIVATE KEY') -> bytes:
        """
        Exports the full RSA instance into DER-encoded bytes.
        See https://tools.ietf.org/html/rfc2313#section-7.2.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of RSA instance.
        """
        return export_der([0, self.n, self.e, self.alt_d, self.p, self.q, self.d % (self.p-1), self.d % (self.q-1), mod_inv(self.q, self.p)], encode_pem, marker)



    def export_public_key(self, encode_pem: bool=True, marker: str='RSA PUBLIC KEY') -> bytes:
        """
        Exports the only the public parameters of the RSA instance into DER-encoded bytes.
        See https://tools.ietf.org/html/rfc2313#section-7.2.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of RSA instance.
        """
        return export_der([self.n, self.e], encode_pem, marker)

    

    @staticmethod
    def import_key(buffer: bytes):
        """
        Builds an RSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffers (bytes): DER and/or PEM-encoded bytes.
        
        Returns:
            RSA: RSA instance.
        """
        items = bytes_to_der_sequence(buffer)

        # PKCS#1
        if len(items) == 9 and int(items[0]) == 0:
            items = [int(item) for item in items]
            del items[6:]
            del items[0]
            n, e, _d, p, q, = items
            rsa = RSA(0, p=p, q=q, e=e)

        elif len(items) == 2:
            if type(items[1]) is BitString:
                if str(items[0][0]) == '1.2.840.113549.1.1.1':
                    bitstring_seq = decoder.decode(Bytes(int(items[1])))[0]
                    items = list(bitstring_seq)
                else:
                    raise ValueError('Unable to decode RSA key.')

            n, e = [int(item) for item in items]
            rsa = RSA(2, e=e)
            rsa.n = n

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