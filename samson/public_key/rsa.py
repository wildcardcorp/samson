from samson.utilities.math import gcd, lcm, mod_inv, find_prime
from samson.utilities.encoding import export_der, bytes_to_der_sequence, parse_openssh
from samson.utilities.pem import pem_encode, pem_decode
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import Integer, ObjectIdentifier, BitString, SequenceOf, Sequence, Null
from samson.utilities.bytes import Bytes
import base64
import math
import random

class RSA(object):
    """
    Rivest-Shamir-Adleman public key cryptosystem
    """

    def __init__(self, bits: int, p: int=None, q: int=None, e: int=65537):
        """
        Parameters:
            bits (int): Number of bits for strength and capacity.
            p (int): Secret prime modulus.
            q (int): Secret prime modulus.
            e (int): Public exponent.
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



    def export_private_key(self, encode_pem: bool=True, marker: str='RSA PRIVATE KEY', encryption: str=None, passphrase: bytes=None, iv: bytes=None) -> bytes:
        """
        Exports the full RSA instance into DER-encoded bytes.
        See https://tools.ietf.org/html/rfc2313#section-7.2.

        Parameters:
            encode_pem  (bool): Whether or not to PEM-encode as well.
            marker       (str): Marker to use in PEM formatting (if applicable).
            encryption   (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
            passphrase (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
            iv         (bytes): (Optional) IV to use for CBC encryption.
        
        Returns:
            bytes: DER-encoding of RSA instance.
        """
        der = export_der([0, self.n, self.e, self.alt_d, self.p, self.q, self.d % (self.p-1), self.d % (self.q-1), mod_inv(self.q, self.p)])

        if encode_pem:
            der = pem_encode(der, marker, encryption=encryption, passphrase=passphrase, iv=iv)

        return der



    def export_public_key(self, encode_pem: bool=True, marker: str='PUBLIC KEY') -> bytes:
        """
        Exports the only the public parameters of the RSA instance into DER-encoded bytes.
        See https://tools.ietf.org/html/rfc2313#section-7.2.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of RSA instance.
        """
        seq = Sequence()
        seq.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        seq.setComponentByPosition(1, Null())

        param_seq = SequenceOf()
        param_seq.append(Integer(self.n))
        param_seq.append(Integer(self.e))

        param_bs = bin(Bytes(encoder.encode(param_seq)).int())[2:]
        param_bs = param_bs.zfill(math.ceil(len(param_bs) / 8) * 8)
        param_bs = BitString(param_bs)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, seq)
        top_seq.setComponentByPosition(1, param_bs)

        der_encoded = encoder.encode(top_seq)

        if encode_pem:
            der_encoded = pem_encode(der_encoded, marker)

        return der_encoded



    @staticmethod
    def import_key(buffer: bytes, passphrase: bytes=None):
        """
        Builds an RSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffer     (bytes): DER and/or PEM-encoded bytes.
            passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
        
        Returns:
            RSA: RSA instance.
        """

        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer, passphrase)

        ssh_header = b'ssh-rsa'

        if ssh_header in buffer:
            # SSH public key?
            if buffer.startswith(ssh_header):
                buffer = base64.b64decode(buffer.split(b' ')[1])


            key_parts = parse_openssh(ssh_header, buffer)

            # Public key?
            if len(key_parts) == 3:
                n, e = key_parts[2].int(), key_parts[1].int()
                rsa = RSA(2, e=e)
                rsa.n = n
            else:
                n, e, _, _, p, q, _host = [part.int() for part in key_parts[4:]]
                rsa = RSA(0, p=p, q=q, e=e)

            rsa.n = n

        else:
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
            else:
                raise ValueError("Unable to parse provided RSA key.")

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
