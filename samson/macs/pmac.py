from samson.utilities.bytes import Bytes
from samson.kdfs.s2v import dbl
from types import FunctionType

class PMAC(object):
    """
    Parallelizable message authentication code.
    http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm
    """

    def __init__(self, encryptor: FunctionType, block_size: int=16):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            block_size (int): Block size of cipher.
        """
        self.encryptor = encryptor
        self.block_size = block_size
        self.L = [self.encryptor(Bytes(b'').zfill(self.block_size))]

        result = (self.L[0].int() >> 1)
        if self.L[0].int() & 1:
            result ^= 0x80000000000000000000000000000043

        self.L_inv = result

        for i in range(1, 32):
            self.L.append(dbl(self.L[i-1]))



    def __repr__(self):
        return f"<PMAC: encryptor={self.encryptor}, block_size={self.block_size}, L={self.L}>"

    def __str__(self):
        return self.__repr__()



    def ntz(self, i):
        return bin(i)[::-1].index('1')


    def generate(self, message: bytes, offset=None) -> Bytes:
        """
        Generates a keyed MAC for `message`.

        Parameters:
            message (bytes): Message to generate a MAC for.
        
        Returns:
            Bytes: The MAC.
        """
        message = Bytes.wrap(message)

        incomplete_block = len(message) % self.block_size
        message_chunks = message.chunk(self.block_size, allow_partials=True)
        offset = offset or Bytes(0x0).zfill(self.block_size)
        sigma  = Bytes(0x0).zfill(self.block_size)

        if not message_chunks:
            message_chunks = [message]


        for i in range(len(message_chunks) - 1):
            offset ^= self.L[self.ntz(i+1)]
            sigma  ^= self.encryptor(offset ^ message_chunks[i])


        M_last = message_chunks[-1]

        if incomplete_block or not len(message):
            M_last += b'\x80'
            M_last  = (M_last + (b'\x00' * (self.block_size - len(M_last))))

        sigma ^= M_last

        if len(message) % self.block_size == 0:
            sigma ^= self.L_inv

        return self.encryptor(sigma)
