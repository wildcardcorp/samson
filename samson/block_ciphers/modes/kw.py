from types import FunctionType
from samson.utilities.bytes import Bytes

class KW(object):
    """Key wrap cipher mode."""

    RFC3394_IV = Bytes(0xA6A6A6A6A6A6A6A6)
    RFC5649_IV = Bytes(0xA65959A6)

    def __init__(self, encryptor: FunctionType, decryptor: FunctionType, iv: bytes=RFC3394_IV, block_size: int=16):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            decryptor (func): Function that takes in a ciphertext and returns a plaintext.
            iv       (bytes): Bytes-like initialization vector.
            block_size (int): Block size of the underlying encryption algorithm.
        """
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.iv = iv


    def __repr__(self):
        return f"<KW: encryptor={self.encryptor}, iv={self.iv}>"

    def __str__(self):
        return self.__repr__()


    def encrypt(self, plaintext: bytes, pad: bool=False) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
            pad        (bool): Whether or not to use RFC5649 padding.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        iv = self.iv
        length = len(plaintext)
        plaintext = Bytes.wrap(plaintext)

        if pad:
            r = ((length) + 7) // 8
            plaintext = plaintext + ((r * 8) - length) * b'\x00'
            iv = self.iv + Bytes(length).zfill(4)

        A = iv
        R = plaintext.chunk(8)
        n = len(R)

        # RFC5649 specific
        if n == 1:
            return self.encryptor(iv + plaintext)

        for j in range(6):
            for i in range(n):
                ct = self.encryptor(A + R[i])
                A, R[i] = ct[:8], ct[8:]
                A ^= Bytes(n * j + i + 1).zfill(len(A))

        return A + b''.join(R)



    def decrypt(self, ciphertext: bytes, unpad: bool=False, verify: bool=True) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
            unpad       (bool): Whether or not to unpad with RFC5649 padding.
            verify      (bool): Whether or not to check if the IV is correct.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)

        A = ciphertext[:8]
        R = ciphertext[8:].chunk(8)
        n = len(R)

        if n == 1:
            pt = self.decryptor(ciphertext)
            A, plaintext = pt[:8], pt[8:]
        else:
            for j in reversed(range(6)):
                for i in reversed(range(n)):
                    A ^= Bytes(n * j + i + 1).zfill(len(A))
                    ct = self.decryptor(A + R[i])
                    A, R[i] = ct[:8], ct[8:]

            plaintext = b''.join(R)


        if verify:
            assert A[:len(self.iv)] == self.iv

        if unpad:
            plaintext = plaintext[:A[len(self.iv):].int()]


        return Bytes.wrap(plaintext)
