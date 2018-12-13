from samson.utilities.manipulation import left_rotate, get_blocks
from samson.utilities.bytes import Bytes
from samson.stream_ciphers.salsa import Salsa
from copy import deepcopy

# from samson.utilities
# https://en.wikipedia.org/wiki/Salsa20


def QUARTER_ROUND(a: int, b: int, c: int, d: int) -> (int, int, int, int):
    """
    Performs a quarter round of ChaCha.

    Parameters:
        a (int): ChaCha state variable.
        b (int): ChaCha state variable.
        c (int): ChaCha state variable.
        d (int): ChaCha state variable.
    
    Returns:
        (int, int, int, int): New values for (a, b, c, d).
    """
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = left_rotate(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = left_rotate(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = left_rotate(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = left_rotate(b, 7)
    return a, b, c, d


class ChaCha(Salsa):
    """
    ChaCha stream cipher

    Add-rotate-xor (ARX) structure.
    """

    def __init__(self, key: bytes, nonce: bytes, rounds: int=20, constant: bytes=b"expand 32-byte k"):
        """
        Parameters:
            key      (bytes): Key (128 or 256 bits).
            nonce    (bytes): Nonce (8 bytes).
            rounds     (int): Number of rounds to perform.
            constant (bytes): Constant used in generating the keystream (16 bytes).
        """
        self.key = key
        self.nonce = nonce
        self.rounds = rounds
        self.constant = constant



    def __repr__(self):
        return f"<ChaCha: key={self.key}, nonce={self.nonce}, rounds={self.rounds}, constant={self.constant}>"

    def __str__(self):
        return self.__repr__()


    def full_round(self, block_num: int, state: list=None) -> Bytes:
        """
        Performs a full round of ChaCha.

        Parameters:
            block_num (int): Current block number.
        
        Returns:
            Bytes: Keystream block.
        """
        ctr_bytes = int.to_bytes(block_num, 4, 'little')

        x = state or [
            *[int.from_bytes(block, 'little') for block in get_blocks(self.constant, 4)],
            *[int.from_bytes(block, 'little') for block in get_blocks(self.key, 4)],
                int.from_bytes(ctr_bytes, 'little'),
            *[int.from_bytes(block, 'little') for block in get_blocks(self.nonce, 4)]
        ]


        tmp = deepcopy(x)

        for _ in range(self.rounds // 2):
            # Odd round
            x[0], x[4], x[ 8], x[12] = QUARTER_ROUND(x[0], x[4], x[ 8], x[12])
            x[1], x[5], x[ 9], x[13] = QUARTER_ROUND(x[1], x[5], x[ 9], x[13])
            x[2], x[6], x[10], x[14] = QUARTER_ROUND(x[2], x[6], x[10], x[14])
            x[3], x[7], x[11], x[15] = QUARTER_ROUND(x[3], x[7], x[11], x[15])

            # Even round
            x[0], x[5], x[10], x[15] = QUARTER_ROUND(x[0], x[5], x[10], x[15])
            x[1], x[6], x[11], x[12] = QUARTER_ROUND(x[1], x[6], x[11], x[12])
            x[2], x[7], x[ 8], x[13] = QUARTER_ROUND(x[2], x[7], x[ 8], x[13])
            x[3], x[4], x[ 9], x[14] = QUARTER_ROUND(x[3], x[4], x[ 9], x[14])

        for i in range(16):
            x[i] += tmp[i]

        return Bytes(b''.join([int.to_bytes(state_int & 0xFFFFFFFF, 4, 'little') for state_int in x]), byteorder='little')
