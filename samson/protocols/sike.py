from samson.hashes.sha3 import SHAKE256
from samson.utilities.bytes import Bytes
from samson.ace.decorators import register_primitive
from samson.core.primitives import KeyExchangeAlg, Primitive
from samson.core.metadata import SizeType, SizeSpec, FrequencyType
from samson.protocols.sidh import SIDH, extract_prime_powers
from samson.math.algebra.curves.montgomery_curve import MontgomeryCurve


def G(m, e):
    return SHAKE256(e).hash(m)

H = G

def encode_fp2(fp2):
    p    = fp2[0].ring.characteristic()
    blen = (p.bit_length() + 7) // 8
    return b''.join([Bytes(int(a), 'little').zfill(blen) for a in fp2][::-1])


def decode_fp2(fp2, fp2_bytes):
    p      = fp2.characteristic()
    blen   = (p.bit_length() + 7) // 8
    chunks = [chunk.int() for chunk in Bytes.wrap(fp2_bytes, 'little').chunk(blen)]
    i      = fp2.symbol

    return [fp2(a + b*i) for b,a in zip(chunks[::2], chunks[1::2])]


def F(j, n):
    j_bytes = encode_fp2(j)
    return SHAKE256(n).hash(j_bytes)




@register_primitive()
class SIKE(KeyExchangeAlg):
    """
    Supersingular Isogeny Key Encapsulation.
    """
    KEY_SIZE        = SizeSpec(size_type=SizeType.ARBITRARY, typical=[434, 503, 610, 751])
    USAGE_FREQUENCY = FrequencyType.UNUSUAL

    def __init__(self, curve: 'EllipticCurve', Pa: 'WeierstrassPoint', Qa: 'WeierstrassPoint', Ra: 'WeierstrassPoint', Pb: 'WeierstrassPoint', Qb: 'WeierstrassPoint', Rb: 'WeierstrassPoint', use_a: bool, n: int, m: int=None):
        """
        Parameters:
            curve (EllipticCurve): Starting curve.
            Pa (WeierstrassPoint): `A`'s `P` point.
            Qa (WeierstrassPoint): `A`'s `Q` point.
            Pb (WeierstrassPoint): `B`'s `P` point.
            Qb (WeierstrassPoint): `B`'s `Q` point.
            use_a          (bool): Whether to use `A` points or `B` points.
            n               (int): Bit strength.
            m               (int): `Q` coefficient.
        """
        Primitive.__init__(self)

        self.sidh_params = curve, Pa, Qa, Pb, Qb, use_a
        self.n    = n
        self.sidh = SIDH(*self.sidh_params, n=1)
        self.R    = Ra if use_a else Rb
    

    def __reprdir__(self):
        return ['n', 'sidh']


    def encrypt(self, key: int, message: bytes, public_key: tuple) -> (tuple, 'Bytes'):
        sidh  = SIDH(*self.sidh_params, n=1, m=key)
        j_inv = sidh.derive_key(public_key)
        return (sidh.iU, sidh.iV, sidh.phi(self.R)), message ^ F(j_inv, len(message)*8)


    def decrypt(self, public_key, ciphertext: bytes):
        return self.encrypt(self.sidh.m, ciphertext, public_key)[1]


    def encapsulate(self, public_key_bytes: bytes):
        m      = Bytes.random(self.n // 8)
        r      = G(m + public_key_bytes, self.sidh.prime_power[1])
        c0, c1 = self.encrypt(key=r.int(), message=m, public_key=self.reconstruct_curve(public_key_bytes))

        K = H(m + (c0, c1), self.n)
        return c0, c1, K


    def decapsulate(self, c0, c1):
        m = self.decrypt(c0, c1)
        #r = G(m + self.pub, self.sidh.prime_power[1])
        return H(m + (c0, c1), self.n)


    def reconstruct_curve(self, public_key_bytes: bytes):
        p, q, r = decode_fp2(self.sidh.curve.ring, public_key_bytes)
        A = (1-p*q-p*r-q*r)**2/(4*p*q*r) - p - q - r
        return MontgomeryCurve(A).to_weierstrass_form()
