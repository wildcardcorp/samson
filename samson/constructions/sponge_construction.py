from math import ceil
from samson.utilities.bytes import Bytes
from types import FunctionType

class SpongeConstruction(object):
    """
    "The sponge construction is a mode of operation, based on a fixed-length permutation (or transformation) and on a padding rule, which builds a function mapping variable-length input to variable-length output"
    https://keccak.team/sponge_duplex.html
    """

    def __init__(self, perm_func: FunctionType, pad_func: FunctionType, r: int, c: int):
        """
        Parameters:
            perm_func (func): Sponge permutation function.
            pad_func  (func): Function for padding messages. Takes in bytes and returns them with padding.
            r          (int): Bit-size of the sponge function.
            c          (int): Sponge capacity.
        """
        self.perm_func = perm_func
        self.pad_func = pad_func

        self.r = r
        self.c = c

        self.block_size = (self.r + 7) // 8

        self.S = [[0] * 5 for _ in range(5)]


    def __repr__(self):
        return f"<Sponge r={self.r}, c={self.c}, block_size={self.block_size}, S={self.S}, pad_func={self.pad_func}>"

    def __str__(self):
        return self.__repr__()


    def reset(self):
        """
        Resets the sponge to its initial state.
        """
        self.S = [[0] * 5 for _ in range(5)]



    def absorb(self, in_bytes: bytes):
        """
        Absorbs bytes into the sponge.

        Parameters:
            in_bytes (bytes): Bytes to absorb.
        """
        padded = self.pad_func(in_bytes)

        for block in padded.chunk(self.block_size):
            curr = 0
            for y in range(5):
                for x in range(5):
                    self.S[x][y] ^= sum([byte << i * 8 for i, byte in enumerate(block[curr:curr + 8])])
                    curr += 8

            self.S = self.perm_func(self.S)



    def squeeze(self, amount: int):
        """
        Squeezes bytes out of the sponge.

        Parameters:
            amount (int): Number of bytes to return.
        
        Return:
            generator: Yields blocks of Bytes until at least request `amount` has been returned.
        """
        for _ in range(ceil(amount / self.block_size)):
            out = Bytes(b'')
            for y in range(5):
                for x in range(5):
                    out += Bytes(self.S[x][y]).zfill(8)[::-1]

            yield out[:self.block_size]
            self.S = self.perm_func(self.S)
