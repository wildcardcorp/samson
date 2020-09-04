from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.cbc import CBC
from samson.core.primitives import EncryptionAlg, BlockCipherMode, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec
from samson.ace.decorators import register_primitive

# https://en.wikipedia.org/wiki/Ciphertext_stealing
# CTS-3
@register_primitive()
class CBCCTS(BlockCipherMode):
    """Cipherblock chaining with ciphertext stealing block cipher mode."""

    EPHEMERAL = EphemeralSpec(ephemeral_type=EphemeralType.IV, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE))

    def __init__(self, cipher: EncryptionAlg, iv: bytes):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Bytes-like initialization vector.
        """
        Primitive.__init__(self)
        self.underlying_mode = CBC(cipher, iv)



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext  = Bytes.wrap(plaintext)
        block_size = self.underlying_mode.cipher.block_size
        pt_len     = len(plaintext)
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
        block_size = self.underlying_mode.cipher.block_size
        ct_chunks  = ciphertext.chunk(block_size, allow_partials=True)
        ct_len     = len(ciphertext)

        padding_len = (block_size - (ct_len % block_size)) % block_size

        D_n = self.underlying_mode.cipher.decrypt(ct_chunks[-2])
        C_n = sum(ct_chunks[:-2]) + ct_chunks[-1] + D_n[-padding_len:][:padding_len] + ct_chunks[-2]

        return self.underlying_mode.decrypt(C_n, unpad=False)[:ct_len]
