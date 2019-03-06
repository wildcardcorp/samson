from samson.macs.cbc_mac import CBCMAC
from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael
from samson.core.mac import MAC

class CMAC(MAC):
    """
    Message authentication code scheme based off of CBCMAC.
    """

    def __init__(self, key: bytes, cipher: object=Rijndael, iv: bytes=b'\x00' * 16, block_size: int=16):
        """
        Parameters:
            key      (bytes): Bytes-like object to key the underlying cipher.
            cipher   (class): Instantiable class representing a block cipher.
            iv       (bytes): Initialization vector for CBC mode.
            block_size (int): Block size of cipher.
        """
        self.key = key
        self.cipher = cipher
        self.block_size = block_size
        self.k1, self.k2 = self.generate_subkeys()
        self.cbc_mac = CBCMAC(key, cipher, iv)


    def __repr__(self):
        return f"<CMAC: key={self.key}, cipher={self.cipher}, k1={self.k1}, k2={self.k2}>"

    def __str__(self):
        return self.__repr__()


    # https://tools.ietf.org/html/rfc4493#section-2.3
    def generate_subkeys(self) -> (bytes, bytes):
        """
        Internal function used to generate CMAC subkeys `k1` and `k2`.
        """
        L = self.cipher(self.key).encrypt(Bytes(b'').zfill(self.block_size))

        if L.int() & 0x80000000000000000000000000000000:
            K1 = (L << 1) ^ 0x00000000000000000000000000000087
        else:
            K1 = L << 1

        if K1.int() & 0x80000000000000000000000000000000:
            K2 = (K1 << 1) ^ 0x00000000000000000000000000000087
        else:
            K2 = K1 << 1

        return K1, K2


    def generate(self, message: bytes) -> Bytes:
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

        if len(message_chunks) == 0:
            message_chunks = [Bytes(b'')]

        M_last = message_chunks[-1]

        if incomplete_block or not len(message):
            M_last += b'\x80'
            M_last  = (M_last + (b'\x00' * (self.block_size - len(M_last)))) ^ self.k2
        else:
            M_last ^= self.k1

        return self.cbc_mac.generate(b''.join(message_chunks[:-1]) + M_last, pad=False)
