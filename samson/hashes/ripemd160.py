from samson.utilities.bytes import Bytes
from samson.utilities.manipulation import left_rotate
from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction

# http://cacr.uwaterloo.ca/hac/about/chap9.pdf
RL = [
    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ],
    [ 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 ],
    [ 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12 ],
    [ 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2 ],
    [ 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 ]
]

RR = [
    [ 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12 ],
    [ 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2 ],
    [ 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13 ],
    [ 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14 ],
    [ 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 ]
]


SL = [
    [ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 ],
    [ 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12 ],
    [ 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5 ],
    [ 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 ],
    [ 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 ]
]

SR = [
    [ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6 ],
    [ 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11 ],
    [ 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5 ],
    [ 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 ],
    [ 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 ]
]


F1 = lambda x, y, z: x ^ y ^ z
F2 = lambda x, y, z: (x & y) | (~x & z)
F3 = lambda x, y, z: (x | ~y) ^ z
F4 = lambda x, y, z: (x & z) | (y & ~z)
F5 = lambda x, y, z: x ^ (y | ~z)

FL = [F1, F2, F3, F4, F5]
FR = [F5, F4, F3, F2, F1]

KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

INIT_STATE = Bytes(int.to_bytes(0x0123456789ABCDEFFEDCBA9876543210F0E1D2C3, 20, 'big'), byteorder='little')



def COMPRESS(message, state):
    # The authors of RIPEMD160 couldn't decide on whether to use big or little endian, so they used both!
    # RIPEMD160 takes in bytes as big endian but operates and outputs bytes of little endian. Man, was this 'fun.'

    h = [chunk.to_int() for chunk in state.chunk(4)]
    msg_chunks = [chunk[::-1].to_int() for chunk in Bytes.wrap(message, byteorder='big').chunk(4)]

    AL = AR = h[0]
    BL = BR = h[1]
    CL = CR = h[2]
    DL = DR = h[3]
    EL = ER = h[4]

    for curr_round in range(5):
        for w in range(16):
            T = left_rotate(AL + FL[curr_round](BL, CL, DL) + msg_chunks[RL[curr_round][w]] + KL[curr_round], SL[curr_round][w]) + EL
            AL = EL & 0xFFFFFFFF; EL = DL & 0xFFFFFFFF; DL = left_rotate(CL, 10); CL = BL & 0xFFFFFFFF; BL = T & 0xFFFFFFFF

            T = left_rotate(AR + FR[curr_round](BR, CR, DR) + msg_chunks[RR[curr_round][w]] + KR[curr_round], SR[curr_round][w]) + ER
            AR = ER & 0xFFFFFFFF; ER = DR & 0xFFFFFFFF; DR = left_rotate(CR, 10); CR = BR & 0xFFFFFFFF; BR = T & 0xFFFFFFFF

    T = (h[1] + CL + DR) & 0xFFFFFFFF
    h[1] = (h[2] + DL + ER) & 0xFFFFFFFF
    h[2] = (h[3] + EL + AR) & 0xFFFFFFFF
    h[3] = (h[4] + AL + BR) & 0xFFFFFFFF
    h[4] = (h[0] + BL + CR) & 0xFFFFFFFF
    h[0] = T

    return sum([Bytes(state, 'little').zfill(4) for state in h])


class RIPEMD160(MerkleDamgardConstruction):
    """
    Stands for RACE Integrity Primitives Evaluation Message Digest (RIPEMD). While there exist other
    versions of RIPEMD (128, 256, and 320), 160 is the most popular.
    """

    def __init__(self, initial_state: bytes=INIT_STATE):
        """
        Parameters:
            initial_state (bytes): (Optional) Initial internal state.
        """
        super().__init__(
            initial_state=initial_state,
            compression_func=COMPRESS,
            digest_size=20,
            endianness='little'
        )


    def __repr__(self):
        return f"<RIPEMD160: initial_state={self.initial_state}, block_size={self.block_size}>"


    def __str__(self):
        return self.__repr__()
