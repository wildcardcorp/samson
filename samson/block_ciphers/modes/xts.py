from samson.utilities.bytes import Bytes
from types import FunctionType

class XTS(object):
    """
    Xor-encrypt-xor-based tweaked-codebook mode with ciphertext stealing.
    https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS


    This is basically XEX with conditional CTS. Padding the plaintext to the 16-byte boundary
    should, therefore, result in a correct execution of XEX.

    https://en.wikipedia.org/wiki/Disk_encryption_theory#Xor%E2%80%93encrypt%E2%80%93xor_(XEX)
    """

    def __init__(self, encryptor: FunctionType, decryptor: FunctionType, sector_encryptor: FunctionType):
        """
        Parameters:
            encryptor        (func): Function that takes in a plaintext and returns a ciphertext.
            decryptor        (func): Function that takes in a ciphertext and returns a plaintext.
            sector_encryptor (func): Function that takes in a plaintext and returns a ciphertext.
        """
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.sector_encryptor = sector_encryptor



    def __repr__(self):
        return f"<XTS: encryptor={self.encryptor}, decryptor={self.decryptor}, sector_encryptor={self.sector_encryptor}>"

    def __str__(self):
        return self.__repr__()



    def _xts(self, in_bytes: bytes, tweak: int, func: FunctionType, reverse_cts: bool=False) -> Bytes:
        in_bytes = Bytes.wrap(in_bytes)
        tweak_bytes = Bytes(tweak)

        X = self.sector_encryptor(tweak_bytes + b'\x00' * (16 - len(tweak_bytes)))[::-1].int()

        out_bytes = Bytes(b'')
        byte_chunks = in_bytes.chunk(16, allow_partials=True)

        for block in byte_chunks:
            if len(block) == 16:
                if X >> 128:
                    X ^= 0x100000000000000000000000000000087

                X = Bytes(X, 'little').zfill(16)
                out_bytes += func(block ^ X) ^ X

                X = X.int()
                X <<= 1
            else:
                curr_X = X
                if X >> 128:
                    X ^= 0x100000000000000000000000000000087

                # Decryption needs to reverse the ordering of the X's.
                # Here I just throw out the last block, use the most recent X,
                # and then backpedal X.
                if reverse_cts:
                    out_bytes = out_bytes[:-16]
                    X = Bytes(X, 'little').zfill(16)
                    last_chunk = func(byte_chunks[-2] ^ X) ^ X
                    X = curr_X >> 1
                else:
                    out_bytes, last_chunk = out_bytes[:-16], out_bytes[-16:]

                stolen, left_over = last_chunk[len(block):], last_chunk[:len(block)]
                padded_block = block + stolen
                X = Bytes(X, 'little').zfill(16)
                out_bytes += (func(padded_block ^ X) ^ X) + left_over


        return out_bytes



    def encrypt(self, plaintext: bytes, tweak: int) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
            tweak       (int): Number that 'tweaks' the permutation.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        return self._xts(plaintext, tweak, self.encryptor, reverse_cts=False)



    def decrypt(self, ciphertext: bytes, tweak: int) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be decrypted.
            tweak       (int): Number that 'tweaks' the permutation.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        return self._xts(ciphertext, tweak, self.decryptor, reverse_cts=True)
