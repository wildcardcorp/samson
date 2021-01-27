from samson.utilities.bytes import Bytes
from samson.core.primitives import MAC, Primitive
from samson.core.metadata import FrequencyType, ConstructionType, SecurityProofType
from samson.ace.decorators import register_primitive

_MOD_128 = 2**128

@register_primitive()
class Poly1305(MAC):
    """
    Message authentication code using an underlying block cipher. The (r, nonce) combination MUST
    be unique to guarantee its security properties. A single reuse can allow for a forgery.

    References:
        "The Poly1305-AES message-authentication code" (https://cr.yp.to/mac/poly1305-20050329.pdf)
    """

    P1305 = (1 << 130) - 5
    USAGE_FREQUENCY    = FrequencyType.NORMAL
    CONSTRUCTION_TYPES = [ConstructionType.WEGMAN_CARTER]
    SECURITY_PROOF     = SecurityProofType.INFORMATION_THEORETIC

    def __init__(self, r: bytes, clamp_r: bool=True):
        """
        Parameters:
            r      (bytes): Bytes-like polynomial.
            clamp_r (bool): Whether or not to clamp `r` to ensure correctness. Assumes `r` is big endian.
        """
        Primitive.__init__(self)

        if clamp_r:
            self.r = Poly1305._clamp_r(Bytes.wrap(r).change_byteorder()).to_int()
        else:
            self.r = Bytes.wrap(r, byteorder='little').int()



    def __reprdir__(self):
        return ['r']


    # https://tools.ietf.org/html/rfc7539#section-2.5
    @staticmethod
    def _clamp_r(r: bytearray) -> bytearray:
        r[3]  &= 15
        r[7]  &= 15
        r[11] &= 15
        r[15] &= 15
        r[4]  &= 252
        r[8]  &= 252
        r[12] &= 252
        return r


    @staticmethod
    def _chunk_message(message: bytes) -> list:
        return [(chunk + b'\x01').zfill(17) for chunk in Bytes.wrap(message, byteorder='little').chunk(16, allow_partials=True)]


    @staticmethod
    def _evaluate(chunks: list, r: int) -> int:
        total = 0
        for chunk in chunks:
            total += chunk.to_int()
            total *= r
            total %= Poly1305.P1305

        return total % _MOD_128



    def generate(self, message: bytes, nonce: bytes) -> Bytes:
        """
        Generates a keyed MAC for `message`.

        Parameters:
            message (bytes): Message to generate a MAC for.
            nonce   (bytes): Bytes-like nonce.
        
        Returns:
            Bytes: The MAC.
        """
        pt_chunks = Poly1305._chunk_message(message)
        total     = Poly1305._evaluate(pt_chunks, self.r)
        return Bytes((Bytes.wrap(nonce).to_int() + total) % _MOD_128, byteorder='little')


    @staticmethod
    def nonce_reuse_attack(msg1: bytes, sig1: bytes, msg2: bytes, sig2: bytes) -> list:
        """
        Given two message-signature pairs generated by Poly1305 using the same key/nonce,
        returns the `key` and the `nonce`.

        Parameters:
            msg1 (bytes): First message.
            sig1 (bytes): First signature.
            msg2 (bytes): Second message.
            sig2 (bytes): Second signature.

        Returns:
            list: List of candidates formatted as (`r` "key", `s` "nonce").

        Examples:
            >>> from samson.macs.poly1305 import Poly1305
            >>> from samson.utilities.bytes import Bytes
            >>> s    = Bytes(0x0103808afb0db2fd4abff6af4149f51b).change_byteorder()
            >>> r    = 0x85d6be7857556d337f4452fe42d506a8
            >>> msg1 = b'Cryptographic Forum Research Group'
            >>> msg2 = b'Hey there friendos! I hope you die'
            >>> p13  = Poly1305(r)
            >>> sig1 = p13.generate(msg1, s).int()
            >>> sig2 = p13.generate(msg2, s).int()
            >>> (p13.r, s.int()) in Poly1305.nonce_reuse_attack(msg2, sig2, msg1, sig1)
            True

        """
        from samson.math.algebra.rings.integer_ring import ZZ
        from samson.math.symbols import Symbol

        # Given (ma, sa) and (mb, sb) as message-signature pairs using the same nonce
        # Assume `ma` and `mb` are both 3 chunks long
        # The Poly1305 generation function is essentially just Horner's method evaluated at `r`
        # plus a secret constant `s` with coefficients in P1305
        # sa = ((((ma1 * r) + ma2) * r) + ma3) * r + s = ma1*r^3 + ma2r*^2 + ma3*r + s

        # The whole thing is then modulo 2^128, making the final equation:
        # sa = ma1*r^3 + ma2*r^2 + ma3*r + s - n*2^128
        # If `s` is reused, we can cancel it (this is basically the Forbidden attack)

        # sa - sb = (ma1*r^3 - mb1*r^3) + (ma2*r^2 - mb2*r^2) + (ma3*r - mb3*r) + (s - s) - (n*2^128 - m*2^128)
        # sa - sb = (ma1 - mb1)*r^3 + (ma2 - mb2)*r^2 + (ma3 - mb3)*r - (n - m)*2^128

        # Since we know `ma` and `mb`, we can calculate these coefficients
        # sa - sb = m1*r^3 + m2*r^2 + m3*r - (n - m)*2^128

        pt1_chunks, pt2_chunks = [Poly1305._chunk_message(message) for message in [msg1, msg2]]
        coeffs = [chunk1.int() - chunk2.int() for chunk1, chunk2 in zip(pt1_chunks, pt2_chunks)]

        sig1, sig2 = [Bytes.wrap(sig, byteorder='little').int() for sig in [sig1, sig2]]

        sig_diff = sig1 - sig2
        R = ZZ/ZZ(Poly1305.P1305)
        P = R[Symbol('x')]
        p = (P(coeffs[::-1]) << 1) - sig_diff

        # Then we move `sa - sb` to the other side
        # m1*r^3 + m2*r^2 + m3*r - (n - m)*2^128 - (sa - sb) = 0

        # By taking the root of this polynomial, we will find `r`. However,
        # we don't know `n` or `m`. What's actually important is the difference between them.
        # We'll call this difference `k` (i.e. `k = n - m`). Note that `k` may be negative,
        # so we need to try those values as well. `n` and `m` are both in [0, 4], so `k` is in [-4, 4].
        # Four is the max value because the polynomial result (`total`) plus the `nonce` is maximally (2^130-6 + 2^128-1) and (2^130-6 + 2^128-1) // 2^128 = 4.
        # If `total` + `nonce` < 2^128, then it's always zero. Lastly, `k` is more likely to be closer to zero
        # than the extremes, so we try middle values first.

        candidates = []

        k = 0
        while abs(k) < 5:
            roots = p.roots()

            for r in roots:
                ri = int(r)

                # `r` is a 128-bit number, so if the root is bigger than that, we can skip it
                if ri < _MOD_128:
                    test_sig1 = Poly1305._evaluate(pt1_chunks, ri)
                    test_sig2 = Poly1305._evaluate(pt2_chunks, ri)

                    # Here we check if the current `r` is correct
                    # (ta - tb) % 2^128 == ((ta + s) - (tb + s)) % 2^128
                    # If it is, since `s` is a 128-bit number, `s < _MOD_128`
                    # and it should also be fully recoverable
                    if (test_sig1 - test_sig2) % _MOD_128 == sig_diff % _MOD_128:
                        s_prime = abs(sig1 - test_sig1)
                        if all([Poly1305(ri, clamp_r=False).generate(msg, s_prime).int() == sig for msg, sig in [(msg1, sig1), (msg2, sig2)]]):
                            candidates.append((ri, s_prime))


            # This is just a simple way of testing 0, -1, 1, -2, 2...
            k += 1
            p += (-1 + 2*(k % 2)) * (_MOD_128*k)

        return list(set(candidates))
