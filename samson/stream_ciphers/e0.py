from samson.prngs.flfsr import FLFSR
from samson.utilities.bytes import Bytes
from sympy.abc import x
from sympy import Poly

FSM_MATRIX = [
    [ 0,  0,  0,  4,  0,  4,  4,  4,  0,  4,  4,  4,  4,  4,  4,  8],
    [12, 12, 12,  8, 12,  8,  8,  8, 12,  8,  8,  8,  8,  8,  8,  4],
    [ 4,  4,  4,  0,  4,  0,  0,  0,  4,  0,  0,  0,  0,  0,  0, 12],
    [ 8,  8,  8, 12,  8, 12, 12, 12,  8, 12, 12, 12, 12, 12, 12,  0],
    [ 5,  1,  1,  1,  1,  1,  1, 13,  1,  1,  1, 13,  1, 13, 13, 13],
    [ 9, 13, 13, 13, 13, 13, 13,  1, 13, 13, 13,  1, 13,  1,  1,  1],
    [ 1,  5,  5,  5,  5,  5,  5,  9,  5,  5,  5,  9,  5,  9,  9,  9],
    [13,  9,  9,  9,  9,  9,  9,  5,  9,  9,  9,  5,  9,  5,  5,  5],
    [14, 14, 14,  2, 14,  2,  2,  2, 14,  2,  2,  2,  2,  2,  2,  6],
    [ 2,  2,  2, 14,  2, 14, 14, 14,  2, 14, 14, 14, 14, 14, 14, 10],
    [10, 10, 10,  6, 10,  6,  6,  6, 10,  6,  6,  6,  6,  6,  6,  2],
    [ 6,  6,  6, 10,  6, 10, 10, 10,  6, 10, 10, 10, 10, 10, 10, 14],
    [11,  7,  7,  7,  7,  7,  7,  3,  7,  7,  7,  3,  7,  3,  3,  3],
    [ 7, 11, 11, 11, 11, 11, 11, 15, 11, 11, 11, 15, 11, 15, 15, 15],
    [15,  3,  3,  3,  3,  3,  3,  7,  3,  3,  3,  7,  3,  7,  7,  7],
    [ 3, 15, 15, 15, 15, 15, 15, 11, 15, 15, 15, 11, 15, 11, 11, 11]
]

OUTPUT_MATRIX = [
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1],
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 0,  1,  1,  0,  1,  0,  0,  1,  1,  0,  0,  1,  0,  1,  1,  0],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1],
    [ 1,  0,  0,  1,  0,  1,  1,  0,  0,  1,  1,  0,  1,  0,  0,  1]
]

E0_CHUNK = 5120
POLY_SIZES = [25, 31, 33, 39]

class E0(object):
    """
    E0 stream cipher

    Used in Bluetooth.
    """

    def __init__(self, kc: list, addr: list, master_clk: list):
        """
        Parameters:
            kc         (list): Session key derived from master key.
            addr       (list): Hardware address.
            master_clk (list): Master clock values.
        """
        self.lfsrs = [
            FLFSR(0, Poly(x**25 + x**20 + x**12 + x**8  + 1)),
            FLFSR(0, Poly(x**31 + x**24 + x**16 + x**12 + 1)),
            FLFSR(0, Poly(x**33 + x**28 + x**24 + x**4  + 1)),
            FLFSR(0, Poly(x**39 + x**36 + x**28 + x**4  + 1))
        ]

        self.kc = kc
        self.addr = addr
        self.master_clk = master_clk
        self.state = 0
        self.key = 0

        self.key_schedule()



    def __repr__(self):
        return f"<E0: key={self.key}, state={self.state}, kc={self.kc}, addr={self.addr}, master_clk={self.master_clk}>"

    def __str__(self):
        return self.__repr__()


    def key_schedule(self):
        """
        Prepares the internal state for encryption.
        """
        ks_input = [None] * 4
        ks_input[0] = ((self.master_clk[3] &  1) | (self.kc[0] << 1) | (self.kc[4] << 9) | (self.kc[8] << 17) | (self.kc[12] << 25) | (self.master_clk[1] << 33) | (self.addr[2] << 41)) & 0xFFFFFFFFFFFFFFFF
        ks_input[1] = (0x1 | (self.master_clk[0] << 3) | (self.kc[1] << 7) | (self.kc[5] << 15) | (self.kc[9] << 23) | (self.kc[13] << 31) | (self.addr[0] << 39) | (self.addr[3] << 47)) & 0xFFFFFFFFFFFFFFFF
        ks_input[2] = ((self.master_clk[3] >> 1) | (self.kc[2] << 1) | (self.kc[6] << 9) | (self.kc[10] << 17) | (self.kc[14] << 25) | (self.master_clk[2] << 33) | (self.addr[4] << 41)) & 0xFFFFFFFFFFFFFFFF
        ks_input[3] = (0x7 | ((self.master_clk[0] >> 4) << 3) | (self.kc[3] << 7) | (self.kc[7] << 15) | (self.kc[11] << 23) | (self.kc[15] << 31) | (self.addr[1] << 39) | (self.addr[5] << 47)) & 0xFFFFFFFFFFFFFFFF

        z = [0] * 16
        z_i = 0
        sv_state = 0

        for i in range(240):
            if i < 39:
                self.state = 0
            elif i == 238:
                sv_state = self.state

            self.shift()

            # 'Disable' LFSRs until they're full
            for j, size in enumerate(POLY_SIZES):
                if i < size and (self.lfsrs[j].state & 1):
                    self.lfsrs[j].state -=1


            for h in range(4):
                self.lfsrs[h].state ^= ks_input[h] & 1

            for j in range(4):
                ks_input[j] >>= 1


            if i >= 111 and i < 239:
                z[(z_i // 8)] >>= 1
                z[(z_i // 8)]  |= self.key << 7
                z_i += 1


        self.lfsrs[0].state = z[0] | (z[4] << 8) | (z[ 8] << 16) | ((z[12]  & 1) << 24)
        self.lfsrs[1].state = z[1] | (z[5] << 8) | (z[ 9] << 16) | ((z[12] >> 1) << 24)
        self.lfsrs[2].state = z[2] | (z[6] << 8) | (z[10] << 16) | (z[13] << 24) | ((z[15]  & 1) << 32)
        self.lfsrs[3].state = z[3] | (z[7] << 8) | (z[11] << 16) | (z[14] << 24) | ((z[15] >> 1) << 32)

        reg_output = self.get_output_bit()
        self.key = OUTPUT_MATRIX[self.state][reg_output] & 1
        self.state = FSM_MATRIX[sv_state][reg_output]



    def get_output_bit(self) -> int:
        """
        Returns the output bit from the summation generator.
        """
        return ((self.lfsrs[0].state >> 23) & 1) | ((self.lfsrs[1].state >> 22) & 2) | ((self.lfsrs[2].state >> 29) & 4) | ((self.lfsrs[3].state >> 28) & 8)



    def shift(self):
        """
        Clocks the LFSRs and calculates the new state.
        """
        for lfsr in self.lfsrs:
            _ = lfsr.clock()

        reg_output = self.get_output_bit()

        old_state = self.state
        self.state = FSM_MATRIX[old_state][reg_output]
        self.key = OUTPUT_MATRIX[old_state][reg_output] & 1



    def generate(self, length: int) -> Bytes:
        """
        Generates `length` of keystream.

        Parameters:
            length (int): Desired length of keystream in bytes.
        
        Returns:
            Bytes: Keystream.
        """
        bits = []
        for _ in range(length * 8):
            bits.append(str(self.key))
            self.shift()

        return Bytes(int(''.join(bits), 2)).zfill(length)
