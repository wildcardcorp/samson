from samson.block_ciphers.modes.ctr import CTR
from samson.utilities.bytes import Bytes
from samson.core.primitives import EncryptionAlg, StreamingBlockCipherMode, Primitive, AuthenticatedCipher
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive

# Reference
# https://github.com/tomato42/tlslite-ng/blob/master/tlslite/utils/aesgcm.py
GCM_REDUCTION_TABLE = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
]


def reverse_bits(int32: int) -> int:
    return int(bin(int32)[2:].zfill(4)[::-1], 2)


@register_primitive()
class GCM(StreamingBlockCipherMode, AuthenticatedCipher):
    """Galois counter mode (GCM) block cipher mode"""

    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.SINGLE, sizes=96))
    AUTH_TAG_SIZE   = SizeSpec(size_type=SizeType.SINGLE, sizes=128)
    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, cipher: EncryptionAlg, H: int=None):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
        """
        Primitive.__init__(self)
        self.cipher = cipher
        self.H      = H or self.cipher.encrypt(b'\x00' * 16).int()
        self.ctr    = CTR(self.cipher, b'\x00' * 8)

        # Precompute the product table
        self.product_table = [0] * 16
        self.product_table[reverse_bits(1)] = self.H

        for i in range(2, 16, 2):
            self.product_table[reverse_bits(i)]     = self.gcm_shift(self.product_table[reverse_bits(i // 2)])
            self.product_table[reverse_bits(i + 1)] = self.product_table[reverse_bits(i)] ^ self.H


    def __reprdir__(self):
        return ['cipher', 'H', 'ctr']


    def clock_ctr(self, nonce: bytes) -> Bytes:
        nonce = Bytes.wrap(nonce)
        if len(nonce) == 12:
            self.ctr.nonce   = nonce
            self.ctr.counter = 1
        else:
            payload = nonce.pad_congruent_right(16) + (b'\x00' * 8) + Bytes(len(nonce) * 8).zfill(8)
            J_0 = Bytes(self.update(0, payload)).zfill(16)
            self.ctr.nonce   = J_0[:15]
            self.ctr.counter = J_0[-1]

        return self.ctr.encrypt(Bytes(b'').zfill(16))



    def encrypt(self, nonce: bytes, plaintext: bytes, data: bytes=b'') -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            nonce     (bytes): Bytes-like nonce.
            plaintext (bytes): Bytes-like object to be encrypted.
            data      (bytes): Bytes-like additional data to be authenticated but not encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        tag_mask = self.clock_ctr(nonce)
        data     = Bytes.wrap(data)

        ciphertext = self.ctr.encrypt(plaintext)
        tag        = self.auth(ciphertext, data, tag_mask)

        return ciphertext + tag



    def decrypt(self, nonce: bytes, authed_ciphertext: bytes, data: bytes=b'') -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            nonce             (bytes): Bytes-like nonce.
            authed_ciphertext (bytes): Bytes-like object to be decrypted.
            data              (bytes): Bytes-like additional data to be authenticated.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        authed_ciphertext    = Bytes.wrap(authed_ciphertext)
        ciphertext, orig_tag = authed_ciphertext[:-16], authed_ciphertext[-16:]

        tag_mask = self.clock_ctr(nonce)
        data     = Bytes.wrap(data)
        tag      = self.auth(ciphertext, data, tag_mask)

        self.verify_tag(tag, orig_tag)

        return self.ctr.decrypt(ciphertext)


    def gcm_shift(self, x: int) -> int:
        high_bit_set = x & 1
        x >>= 1

        if high_bit_set:
            x ^= 0xe1 << (128 - 8)

        return x


    def mul(self, y):
        ret = 0

        for _ in range(0, 128, 4):
            high_bit = ret & 0xF
            ret >>= 4
            ret  ^= GCM_REDUCTION_TABLE[high_bit] << (128 - 16)
            ret  ^= self.product_table[y & 0xF]
            y   >>= 4

        return ret


    def auth(self, ciphertext: Bytes, ad: Bytes, tag_mask: Bytes) -> Bytes:
        y  = 0
        y  = self.update(y, ad)
        y  = self.update(y, ciphertext)
        y ^= (len(ad) << (3 + 64)) | (len(ciphertext) << 3)
        y  = self.mul(y)
        y ^= tag_mask.int()
        return Bytes(int.to_bytes(y, 16, 'big'))



    def update(self, y: int, data: Bytes) -> int:
        for chunk in data.chunk(16):
            y ^= chunk.int()
            y  = self.mul(y)

        extra = len(data) % 16

        if extra != 0:
            block = bytearray(16)
            block[:extra] = data[-extra:]
            y ^= int.from_bytes(block, 'big')
            y  = self.mul(y)
        return y



    @staticmethod
    def nonce_reuse_attack(auth_data_a: bytes, ciphertext_a: bytes, tag_a: bytes, auth_data_b: bytes, ciphertext_b: bytes, tag_b: bytes) -> list:
        """
        Given two message-signature pairs generated by GCM using the same key/nonce,
        returns candidates for the `auth key` and the `tag mask`.

        Parameters:
            auth_data_a  (bytes): First authenticated data.
            ciphertext_a (bytes): First ciphertext.
            tag_a        (bytes): First tag.
            auth_data_b  (bytes): Second authenticated data.
            ciphertext_b (bytes): Second ciphertext.
            tag_b        (bytes): Second tag.

        Returns:
            list: List with entries formatted as (`H` "auth key", `t` "tag mask").
        """
        from samson.math.algebra.all import FF, ZZ
        from samson.math.polynomial import Polynomial
        from samson.math.symbols import Symbol
        from samson.block_ciphers.rijndael import Rijndael

        x = Symbol('x')
        _ = (ZZ/ZZ(2))[x]
        F = FF(2, 128, reducing_poly=x**128 + x**7 + x**2 + x + 1)

        def int_to_elem(a):
            return F([int(bit) for bit in bin(a)[2:].zfill(128)])

        def elem_to_int(a):
            return int(bin(int(a))[2:].zfill(128)[::-1], 2)

        def gcm_to_poly(ad, ciphertext, tag):
            l = (len(ad) << (3 + 64)) | (len(ciphertext) << 3)

            ct_ints = [chunk.int() for chunk in ciphertext.pad_congruent_right(16).chunk(16)[::-1]]
            ad_ints = [chunk.int() for chunk in ad.pad_congruent_right(16).chunk(16)[::-1]]

            return Polynomial([int_to_elem(coeff) for coeff in [tag.int(), l, *ct_ints, *ad_ints]])


        auth_data_a, ciphertext_a, tag_a, auth_data_b, ciphertext_b, tag_b = [Bytes.wrap(item) for item in [auth_data_a, ciphertext_a, tag_a, auth_data_b, ciphertext_b, tag_b]]
        poly_a = gcm_to_poly(auth_data_a, ciphertext_a, tag_a)
        poly_b = gcm_to_poly(auth_data_b, ciphertext_b, tag_b)

        # 3 is the smallest factor of (2**128) - 1
        roots      = (poly_a + poly_b).roots(subgroup_divisor=3)
        candidates = [elem_to_int(r) for r in roots]
        rij        = Rijndael(Bytes.random(16))

        # Compile results
        results = []
        for candidate in candidates:
            gcm      = GCM(rij, H=candidate)
            no_tag_a = gcm.auth(ciphertext_a, auth_data_a, Bytes(0))
            no_tag_b = gcm.auth(ciphertext_b, auth_data_b, Bytes(0))

            # Just to make sure
            if no_tag_a ^ tag_a == no_tag_b ^ tag_b:
                results.append((candidate, no_tag_a ^ tag_a))

        return results


    forbidden_attack = nonce_reuse_attack
