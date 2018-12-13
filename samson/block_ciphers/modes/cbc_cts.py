from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.cbc import CBC
from types import FunctionType

# https://en.wikipedia.org/wiki/Ciphertext_stealing
# CTS-3
class CBCCTS(object):
    """Cipherblock chaining with ciphertext stealing block cipher mode."""

    def __init__(self, encryptor: FunctionType, decryptor: FunctionType, iv: bytes, block_size: int):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            decryptor (func): Function that takes in a ciphertext and returns a plaintext.
            iv       (bytes): Bytes-like initialization vector.
            block_size (int): Block size of the underlying encryption algorithm.
        """
        self.underlying_mode = CBC(encryptor, decryptor, iv, block_size)


    def __repr__(self):
        return f"<CBCCTS: underlying_mode={self.underlying_mode}>"

    def __str__(self):
        return self.__repr__()


    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)
        block_size = self.underlying_mode.block_size
        pt_len = len(plaintext)
        assert pt_len > block_size

        padding_len = (block_size - (pt_len % block_size)) % block_size

        ciphertext_chunks = self.underlying_mode.encrypt(plaintext + b'\x00' * (padding_len), pad=False).chunk(block_size)
        return (sum(ciphertext_chunks[:-2]) + ciphertext_chunks[-1] + ciphertext_chunks[-2])[:pt_len]



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)
        block_size = self.underlying_mode.block_size
        ct_chunks = ciphertext.chunk(block_size, allow_partials=True)
        ct_len = len(ciphertext)

        padding_len = (block_size - (ct_len % block_size)) % block_size

        D_n = self.underlying_mode.decryptor(ct_chunks[-2])
        C_n = sum(ct_chunks[:-2]) + ct_chunks[-1] + D_n[-padding_len:][:padding_len] + ct_chunks[-2]

        return self.underlying_mode.decrypt(C_n, unpad=False)[:ct_len]
