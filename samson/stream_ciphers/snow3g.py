from samson.block_ciphers.rijndael import SBOX as RIJ_SBOX
from samson.utilities.bytes import Bytes

SQ = [
    0x25,0x24,0x73,0x67,0xD7,0xAE,0x5C,0x30,0xA4,0xEE,0x6E,0xCB,0x7D,0xB5,0x82,0xDB,
    0xE4,0x8E,0x48,0x49,0x4F,0x5D,0x6A,0x78,0x70,0x88,0xE8,0x5F,0x5E,0x84,0x65,0xE2,
    0xD8,0xE9,0xCC,0xED,0x40,0x2F,0x11,0x28,0x57,0xD2,0xAC,0xE3,0x4A,0x15,0x1B,0xB9,
    0xB2,0x80,0x85,0xA6,0x2E,0x02,0x47,0x29,0x07,0x4B,0x0E,0xC1,0x51,0xAA,0x89,0xD4,
    0xCA,0x01,0x46,0xB3,0xEF,0xDD,0x44,0x7B,0xC2,0x7F,0xBE,0xC3,0x9F,0x20,0x4C,0x64,
    0x83,0xA2,0x68,0x42,0x13,0xB4,0x41,0xCD,0xBA,0xC6,0xBB,0x6D,0x4D,0x71,0x21,0xF4,
    0x8D,0xB0,0xE5,0x93,0xFE,0x8F,0xE6,0xCF,0x43,0x45,0x31,0x22,0x37,0x36,0x96,0xFA,
    0xBC,0x0F,0x08,0x52,0x1D,0x55,0x1A,0xC5,0x4E,0x23,0x69,0x7A,0x92,0xFF,0x5B,0x5A,
    0xEB,0x9A,0x1C,0xA9,0xD1,0x7E,0x0D,0xFC,0x50,0x8A,0xB6,0x62,0xF5,0x0A,0xF8,0xDC,
    0x03,0x3C,0x0C,0x39,0xF1,0xB8,0xF3,0x3D,0xF2,0xD5,0x97,0x66,0x81,0x32,0xA0,0x00,
    0x06,0xCE,0xF6,0xEA,0xB7,0x17,0xF7,0x8C,0x79,0xD6,0xA7,0xBF,0x8B,0x3F,0x1F,0x53,
    0x63,0x75,0x35,0x2C,0x60,0xFD,0x27,0xD3,0x94,0xA5,0x7C,0xA1,0x05,0x58,0x2D,0xBD,
    0xD9,0xC7,0xAF,0x6B,0x54,0x0B,0xE0,0x38,0x04,0xC8,0x9D,0xE7,0x14,0xB1,0x87,0x9C,
    0xDF,0x6F,0xF9,0xDA,0x2A,0xC4,0x59,0x16,0x74,0x91,0xAB,0x26,0x61,0x76,0x34,0x2B,
    0xAD,0x99,0xFB,0x72,0xEC,0x33,0x12,0xDE,0x98,0x3B,0xC0,0x9B,0x3E,0x18,0x10,0x3A,
    0x56,0xE1,0x77,0xC9,0x1E,0x9E,0x95,0xA3,0x90,0x19,0xA8,0x6C,0x09,0xD0,0xF0,0x86
]

# https://www.gsma.com/aboutus/wp-content/uploads/2014/12/snow3gspec.pdf
# https://github.com/mitshell/CryptoMobile/blob/master/C_alg/SNOW_3G.c
class SNOW3G(object):
    """
    SNOW3G stream cipher

    Used in 4G LTE encryption.
    """

    def __init__(self, key: bytes, iv: bytes):
        """
        Parameters:
            key (bytes): Key (128 or 256 bits).
            iv  (bytes): Initialization vector (16 bytes).
        """
        self.key = Bytes.wrap(key)
        self.iv = Bytes.wrap(iv)

        k0, k1, k2, k3 = [chunk.to_int() for chunk in self.key.chunk(4)]
        iv0, iv1, iv2, iv3 = [chunk.to_int() for chunk in self.iv.chunk(4)]

        s = [None] * 16
        s[15] = k3 ^ iv0
        s[14] = k2
        s[13] = k1
        s[12] = k0 ^ iv1
        s[11] = k3 ^ 0xFFFFFFFF
        s[10] = k2 ^ 0xFFFFFFFF ^ iv2
        s[9] = k1 ^ 0xFFFFFFFF ^ iv3
        s[8] = k0 ^ 0xFFFFFFFF
        s[7] = k3
        s[6] = k2
        s[5] = k1
        s[4] = k0
        s[3] = k3 ^ 0xFFFFFFFF
        s[2] = k2 ^ 0xFFFFFFFF
        s[1] = k1 ^ 0xFFFFFFFF
        s[0] = k0 ^ 0xFFFFFFFF

        self.s = s

        self.R1 = 0
        self.R2 = 0
        self.R3 = 0

        for _ in range(32):
            F = self.clock_FSM()
            self.clock_lfsr(F)



    def __repr__(self):
        return f"<SNOW3G: key={self.key}, iv={self.iv}, s={self.s}, R1={self.self.R1}, R2={self.self.R2}, R3={self.self.R3}>"

    def __str__(self):
        return self.__repr__()



    def MULx(self, V: int, c: int) -> int:
        if V >> 7:
            return ((V << 1) % 256) ^ c
        else:
            return V << 1


    def MULa(self, c: int) -> int:
        return (self.MULxPOW(c, 23, 0xA9) << 24) + (self.MULxPOW(c, 245, 0xA9) << 16) + (self.MULxPOW(c, 48, 0xA9) << 8) + self.MULxPOW(c, 239, 0xA9)


    def DIVa(self, c: int) -> int:
        return (self.MULxPOW(c, 16, 0xA9) << 24) + (self.MULxPOW(c, 39, 0xA9) << 16) + (self.MULxPOW(c, 6, 0xA9) << 8) + self.MULxPOW(c, 64, 0xA9)


    def MULxPOW(self, V: int, i: int, c: int) -> int:
        if i == 0:
            return V
        else:
            return self.MULx(self.MULxPOW(V, i - 1, c), c)



    def S1(self, w: int) -> Bytes:
        return self._perform_sbox_transform(Bytes.wrap(w).zfill(4), RIJ_SBOX, 0x1B, True)


    def S2(self, w: int) -> Bytes:
        return self._perform_sbox_transform(Bytes.wrap(w).zfill(4), SQ, 0x69)


    def _perform_sbox_transform(self, w: bytes, sbox: list, val: int, s2=False) -> Bytes:
        sqw0, sqw1, sqw2, sqw3 = [sbox[w_i] for w_i in w]

        r0 = self.MULx(sqw0, val) ^ sqw1 ^ sqw2 ^ self.MULx(sqw3, val) ^ sqw3
        r1 = self.MULx(sqw0, val) ^ sqw0 ^ self.MULx(sqw1, val)  ^ sqw2 ^ sqw3
        r2 = sqw0 ^ self.MULx(sqw1, val) ^ sqw1  ^ self.MULx(sqw2, val) ^ sqw3
        r3 = sqw0 ^ sqw1 ^ self.MULx(sqw2, val) ^ sqw2 ^ self.MULx(sqw3, val)

        return Bytes([r0, r1, r2, r3]).to_int()


    def clock_FSM(self) -> int:
        """
        Used internally. Clocks the internal FSM.

        Returns:
            int: Next value of `F`.
        """
        F = ((self.s[15] + self.R1) % (2 ** 32)) ^ self.R2
        r = (self.R2 + (self.R3 ^ self.s[5])) % (2 ** 32)
        self.R3 = self.S2(self.R2)
        self.R2 = self.S1(self.R1)
        self.R1 = r

        return F


    def clock_lfsr(self, F: int=None):
        """
        Used internally. Clocks the LFSR and possibly combines with `F`.

        Parameters:
            F (int): Value of `F` to be clocked with.
        """
        v = ((self.s[0] << 8) & 0xFFFFFF00) ^ self.MULa((self.s[0] >> 24) & 0xFF) ^ self.s[2] ^ ((self.s[11] >> 8) & 0x00FFFFFF) ^ self.DIVa(self.s[11] & 0xFF)
        if F:
            v^= F

        for i in range(15):
            self.s[i] = self.s[i + 1]

        self.s[15] = v



    def generate(self, length: int) -> Bytes:
        """
        Generates `length` of keystream.

        Parameters:
            length (int): Desired length of keystream in bytes.
        
        Returns:
            Bytes: Keystream.
        """
        _F = self.clock_FSM()
        self.clock_lfsr()

        ks = []

        for _ in range(length):
            F = self.clock_FSM()
            ks.append(F ^ self.s[0])
            self.clock_lfsr()

        return sum([Bytes(i).zfill(4) for i in ks])
