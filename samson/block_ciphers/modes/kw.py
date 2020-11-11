from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import InvalidMACException
from samson.utilities.runtime import RUNTIME
from samson.core.primitives import EncryptionAlg, BlockCipherMode, Primitive
from samson.ace.decorators import register_primitive

@register_primitive()
class KW(BlockCipherMode):
    """Key wrap cipher mode."""

    # TODO: Err, how does this fit into PSL? These are already defined.
    RFC3394_IV = Bytes(0xA6A6A6A6A6A6A6A6)
    RFC5649_IV = Bytes(0xA65959A6)

    def __init__(self, cipher: EncryptionAlg, iv: bytes=RFC3394_IV):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Bytes-like initialization vector.
        """
        Primitive.__init__(self)
        self.cipher = cipher
        self.iv     = iv



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
            return self.cipher.encrypt(iv + plaintext)

        for j in range(6):
            for i in range(n):
                ct = self.cipher.encrypt(A + R[i])
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
            pt = self.cipher.decrypt(ciphertext)
            A, plaintext = pt[:8], pt[8:]
        else:
            for j in reversed(range(6)):
                for i in reversed(range(n)):
                    A ^= Bytes(n * j + i + 1).zfill(len(A))
                    ct = self.cipher.decrypt(A + R[i])
                    A, R[i] = ct[:8], ct[8:]

            plaintext = b''.join(R)


        if verify:
            if not RUNTIME.compare_bytes(A[:len(self.iv)], self.iv):
                raise InvalidMACException

        if unpad:
            plaintext = plaintext[:A[len(self.iv):].int()]


        return Bytes.wrap(plaintext)
