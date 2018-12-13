from samson.block_ciphers.modes.ctr import CTR
from samson.utilities.bytes import Bytes
from types import FunctionType

# Reference
# https://github.com/tomato42/tlslite-ng/blob/master/tlslite/utils/aesgcm.py
GCM_REDUCTION_TABLE = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
]


def reverse_bits(int16: int) -> int:
    return int(bin(int16)[2:].zfill(4)[::-1], 2)


class GCM(object):
    """Galois counter mode (GCM) block cipher mode"""

    def __init__(self, encryptor: FunctionType):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
        """
        self.encryptor = encryptor
        self.H = self.encryptor(b'\x00' * 16).int()
        self.ctr = CTR(self.encryptor, b'\x00' * 8, 16)

        # Precompute the product table
        self.product_table = [0] * 16
        self.product_table[reverse_bits(1)] = self.H

        for i in range(2, 16, 2):
            self.product_table[reverse_bits(i)] = self.gcm_shift(self.product_table[reverse_bits(i // 2)])
            self.product_table[reverse_bits(i + 1)] = self.product_table[reverse_bits(i)] ^ self.H


    def __repr__(self):
        return f"<GCM: encryptor={self.encryptor}, H={self.H}, ctr={self.ctr}>"


    def __str__(self):
        return self.__repr__()


    def clock_ctr(self, nonce: bytes) -> Bytes:
        nonce = Bytes.wrap(nonce)
        if len(nonce) == 12:
            self.ctr.nonce = nonce
            self.ctr.counter = 1
        else:
            payload = nonce + (b'\x00' * (16 - (len(nonce)) % 16)) + (b'\x00' * 8) + Bytes(len(nonce) * 8).zfill(8)
            J_0 = Bytes(self.update(0, payload)).zfill(16)
            self.ctr.nonce = J_0[:15]
            self.ctr.counter = J_0[-1]

        return self.ctr.encrypt(Bytes(b'').zfill(16))



    def encrypt(self, nonce: bytes, plaintext: bytes, data: bytes) -> Bytes:
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
        data = Bytes.wrap(data)

        ciphertext = self.ctr.encrypt(plaintext)
        tag = self.auth(ciphertext, data, tag_mask)

        return ciphertext + tag



    def decrypt(self, nonce: bytes, authed_ciphertext: bytes, data: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            nonce     (bytes): Bytes-like nonce.
            plaintext (bytes): Bytes-like object to be decrypted.
            data      (bytes): Bytes-like additional data to be authenticated.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext, orig_tag = authed_ciphertext[:-16], authed_ciphertext[-16:]

        tag_mask = self.clock_ctr(nonce)
        data = Bytes.wrap(data)
        tag = self.auth(ciphertext, data, tag_mask)

        # Do I care about constant time?
        if tag != orig_tag:
            raise Exception('Tag mismatch: authentication failed!')

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
            ret ^= GCM_REDUCTION_TABLE[high_bit] << (128 - 16)
            ret ^= self.product_table[y & 0xF]
            y >>= 4

        return ret


    def auth(self, ciphertext: Bytes, ad: Bytes, tag_mask: Bytes) -> Bytes:
        y = 0
        y = self.update(y, ad)
        y = self.update(y, ciphertext)
        y ^= (len(ad) << (3 + 64)) | (len(ciphertext) << 3)
        y = self.mul(y)
        y ^= tag_mask.int()
        return Bytes(int.to_bytes(y, 16, 'big'))



    def update(self, y: int, data: Bytes) -> int:
        for chunk in data.chunk(16):
            y ^= chunk.int()
            y = self.mul(y)

        extra = len(data) % 16

        if extra != 0:
            block = bytearray(16)
            block[:extra] = data[-extra:]
            y ^= int.from_bytes(block, 'big')
            y = self.mul(y)
        return y
