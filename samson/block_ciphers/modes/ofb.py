from samson.block_ciphers.modes.cbc import CBC
from samson.core.primitives import EncryptionAlg, StreamingBlockCipherMode, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec
from samson.ace.decorators import register_primitive
from samson.utilities.bytes import Bytes
from math import ceil

@register_primitive()
class OFB(StreamingBlockCipherMode):
    """Output feedback block cipher mode."""

    EPHEMERAL = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE))

    def __init__(self, cipher: EncryptionAlg, iv: bytes):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Bytes-like initialization vector.
        """
        Primitive.__init__(self)
        self.cipher = cipher
        self.iv     = iv
        self.cbc    = CBC(cipher, iv)


    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext  = Bytes.wrap(plaintext)

        num_blocks = ceil(len(plaintext) / self.cipher.block_size)
        keystream  = self.cbc.encrypt(b'\x00' * self.cipher.block_size * num_blocks, False)

        return keystream[:len(plaintext)] ^ plaintext


    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        return self.encrypt(ciphertext)
