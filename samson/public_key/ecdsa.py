from samson.math.general import mod_inv, random_int_between
from samson.math.algebra.curves.weierstrass_curve import WeierstrassPoint
from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import NoSolutionException
from samson.public_key.dsa import DSA
from samson.hashes.sha2 import SHA256

from samson.encoding.openssh.openssh_ecdsa_key import OpenSSHECDSAPrivateKey, OpenSSHECDSAPublicKey, SSH2ECDSAPublicKey
from samson.encoding.jwk.jwk_ec_private_key import JWKECPrivateKey
from samson.encoding.jwk.jwk_ec_public_key import JWKECPublicKey
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PKCS1ECDSAPrivateKey
from samson.encoding.pkcs8.pkcs8_ecdsa_private_key import PKCS8ECDSAPrivateKey
from samson.encoding.x509.x509_ecdsa_public_key import X509ECDSAPublicKey
from samson.encoding.x509.x509_ecdsa_certificate import X509ECDSACertificate, X509ECDSASigningAlgorithms, X509ECDSACertificateSigningRequest
from samson.encoding.dns_key.dns_key_ecdsa_key import DNSKeyECDSAPublicKey, DNSKeyECDSAPrivateKey
from samson.encoding.general import PKIEncoding
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec, FrequencyType
from samson.core.primitives import Primitive
from samson.ace.decorators import register_primitive
import math

# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
@register_primitive()
class ECDSA(DSA):
    """
    Elliptical Curve Digital Signature Algorithm
    """

    PRIV_ENCODINGS = {
        PKIEncoding.JWK: JWKECPrivateKey,
        PKIEncoding.OpenSSH: OpenSSHECDSAPrivateKey,
        PKIEncoding.PKCS1: PKCS1ECDSAPrivateKey,
        PKIEncoding.PKCS8: PKCS8ECDSAPrivateKey,
        PKIEncoding.DNS_KEY: DNSKeyECDSAPrivateKey
    }


    PUB_ENCODINGS = {
        PKIEncoding.JWK: JWKECPublicKey,
        PKIEncoding.OpenSSH: OpenSSHECDSAPublicKey,
        PKIEncoding.SSH2: SSH2ECDSAPublicKey,
        PKIEncoding.X509_CERT: X509ECDSACertificate,
        PKIEncoding.X509: X509ECDSAPublicKey,
        PKIEncoding.DNS_KEY: DNSKeyECDSAPublicKey,
        PKIEncoding.X509_CSR: X509ECDSACertificateSigningRequest
    }

    X509_SIGNING_ALGORITHMS = X509ECDSASigningAlgorithms
    X509_SIGNING_DEFAULT    = X509ECDSASigningAlgorithms.ecdsa_with_SHA256

    KEY_SIZE        = SizeSpec(size_type=SizeType.RANGE, sizes=[192, 224, 256, 384, 521])
    OUTPUT_SIZE     = SizeSpec(size_type=SizeType.RANGE, typical=[384, 448, 512, 768, 1042])
    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.KEY, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda dsa: dsa.q.bit_length()))
    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, G: WeierstrassPoint, hash_obj: object=SHA256(), d: int=None, Q: WeierstrassPoint=None):
        """
        Parameters:
            G (WeierstrassPoint): Generator point for a curve.
            hash_obj    (object): Instantiated object with compatible hash interface.
            d              (int): (Optional) Private key.
        """
        Primitive.__init__(self)
        self.G = G
        self.q = self.G.order()
        self.d = Bytes.wrap(d).int() if d else random_int_between(1, self.q)
        self.Q = Q or self.d * self.G
        self.hash_obj = hash_obj


    def __reprdir__(self):
        return ['d', 'G', 'Q', 'hash_obj']


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

        k_in = k

        while True:
            k = k_in or random_int_between(1, self.q)
            inv_k = mod_inv(k, self.q)

            z = self.hash_obj.hash(message).int()
            z >>= max(self.hash_obj.digest_size * 8 - self.q.bit_length(), 0)

            r = int((k * self.G).x) % self.q
            s = (inv_k * (z + self.d * r)) % self.q

            if not (s == 0 or r == 0):
                break

            if k_in:
                raise ValueError(f'{k} is not a valid `k` for {message}')

        return (r, s)


    def _build_verification_params(self, message: bytes, sig: (int, int)) -> (int, int, WeierstrassPoint):
        (r, s) = sig
        w = mod_inv(s, self.q)

        z = self.hash_obj.hash(message).int()
        z >>= max(self.hash_obj.digest_size * 8 - self.q.bit_length(), 0)

        u_1 = (z * w) % self.q
        u_2 = (r * w) % self.q
        v = u_1 * self.G + u_2 * self.Q

        return u_1, u_2, v


    def verify(self, message: bytes, sig: (int, int)) -> bool:
        """
        Verifies a `message` against a `sig`.

        Parameters:
            message  (bytes): Message.
            sig ((int, int)): Signature of `message`.

        Returns:
            bool: Whether the signature is valid or not.
        """
        r, _ = sig
        _, _, v = self._build_verification_params(message, sig)
        return v.x == r


    def duplicate_signature_key_selection(self,  message: bytes, sig: (int, int)) -> 'ECDSA':
        """
        Generates an ECDSA instance that signs `message` as `sig`.

        Parameters:
            message  (bytes): Message.
            sig ((int, int)): Desired signature of `message`.

        Returns:
            ECDSA: Constructed ECDSA with duplicate signature.
        """
        u1, u2, v = self._build_verification_params(message, sig)

        d = random_int_between(1, self.q)
        t = u1 + u2*d
        G = v/t
        return ECDSA(G, d=d)


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


    def format_public_point(self) -> str:
        """
        Internal function used for exporting the key. Formats `Q` into a bitstring.
        """
        zero_fill = math.ceil(self.G.curve.order().bit_length() / 8)
        pub_point_bs = bin((b'\x00\x04' + (Bytes(int(self.Q.x)).zfill(zero_fill) + Bytes(int(self.Q.y)).zfill(zero_fill))).int())[2:]
        pub_point_bs = pub_point_bs.zfill(math.ceil(len(pub_point_bs) / 8) * 8)
        return pub_point_bs



    def biased_nonce_key_recovery(self, msgs: list, sigs: list, bias_size: int, is_high_bit_bias: bool) -> 'ECDSA':
        """
        Recovers the private key `d` from ECDSA signatures with high or low bits biased to a constant.

        Parameters:
            msgs             (list): Messages that were signed.
            sigs             (list): Signature pairs that align with `msgs`.
            bias_size         (int): Size of bias in bits.
            is_high_bit_bias (bool): Whether the bias is at the high bits (True) or low bits (False).

        Returns:
            ECDSA: Cracked ECDSA instance.

        Examples:
            >>> from samson.all import *
            >>> start = q.bit_length()
            >>> stop  = start - 64
            >>> c     = random_int(2**64)
            >>> #_____________
            >>> def bad_random(size):
            >>>     k = random_int(size)
            >>>     return (k & (((1 << size.bit_length()) - 1) - ((1 << start) - 1) + ((1 << stop) - 1))) + (c << stop)
            >>> #_____________
            >>> R     = ZZ/ZZ(233970423115425145524320034830162017933)
            >>> curve = WeierstrassCurve(a=R(-95051), b=R(11279326), cardinality=8*29246302889428143187362802287225875743, base_tuple=(182, 85518893674295321206118380980485522083), ring=R)
            >>> q     = curve.G.order()
            >>> n     = 6
            >>> ecdsa = ECDSA(curve.G, d=d)
            >>> #_____________
            >>> ks    = [bad_random(q) for _ in range(n)]
            >>> msgs  = [Bytes.random((q.bit_length() - 1) // 8) for _ in range(n)]
            >>> sigs  = [ecdsa.sign(msg, k=k) for k, msg in zip(ks, msgs)]
            >>> ecdsa.biased_nonce_key_recovery(msgs, sigs, 64, True) == ecdsa
            True

        References:
            https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
            https://toadstyle.org/cryptopals/62.txt
        """
        from samson.math.all import ZZ, QQ, Matrix

        q = self.q
        R = ZZ/ZZ(q)

        # Emulates ECDSA message processing
        def H(m):
            h   = self.hash_obj.hash(m).int()
            h >>= max(self.hash_obj.digest_size * 8 - q.bit_length(), 0)
            return h


        if is_high_bit_bias:
            bias_start = q.bit_length()
            bias_stop  = q.bit_length() - bias_size
        else:
            bias_start = bias_size
            bias_stop  = 0


        bias_denom   = 2**(q.bit_length() - bias_start)
        mn, (rn, sn) = H(msgs[-1]), sigs[-1]

        # Builds the problem matrix
        # Note we use the difference between signatures to zero the bias
        def process_msgs(msgs, sigs):
            n    = len(msgs)-1
            ts   = []
            us   = []
            qs   = []

            for i in range(n):
                qs.append([QQ(0)]*i + [QQ(q)] + [QQ(0)]*(n-i+1))


            mns = R(mn) / sn / bias_denom
            rns = R(rn) / sn / bias_denom

            for m, (r, s) in zip(msgs[:-1], sigs[:-1]):
                t   = R(r) / s / bias_denom - rns
                u   = R(H(m)) / s / bias_denom - mns
                ts.append(QQ(t))
                us.append(QQ(u))


            ts.append(QQ((2**(q.bit_length() - bias_start + bias_stop), q)))
            ts.append(QQ(0))
            us.append(QQ(0))
            us.append(QQ(q))

            return qs + [ts] + [us]


        vecs = process_msgs(msgs, sigs)
        m    = Matrix(vecs)
        sol  = m.LLL(0.99)

        # We only have the difference between `k_i` and `k_n`, so we have
        # to do some addition calculations
        for k_row in [v for v in sol if v[-1] == q]:
            for k_diff, m, (r, s) in zip(k_row[:-1], msgs[:-1], sigs[:-1]):
                m      = H(m)
                k_diff = ZZ(k_diff*bias_denom)
                d      = int(R(sn*m - s*mn - s*sn*(k_diff))/R(rn*s - r*sn))

                if self.G*d == self.Q:
                    return ECDSA(G=self.G, d=d)


        raise NoSolutionException
