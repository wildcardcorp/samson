from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from samson.core.primitives import EncryptionAlg, StreamingBlockCipherMode, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec
from samson.ace.decorators import register_primitive

@register_primitive()
class CFB(StreamingBlockCipherMode):
    """Cipher feedback block cipher mode."""

    EPHEMERAL = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE, typical=[128]))

    def __init__(self, cipher: EncryptionAlg, iv: bytes):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Bytes-like initialization vector.
        """
        Primitive.__init__(self)
        self.cipher = cipher
        self.iv     = iv



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        ciphertext = b''
        plaintext  = Bytes.wrap(plaintext)

        last_block = self.iv

        for block in get_blocks(plaintext, self.cipher.block_size, allow_partials=True):
            enc_block   = self.cipher.encrypt(bytes(last_block))[:len(block)] ^ block
            ciphertext += enc_block
            last_block  = enc_block

        return ciphertext



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        plaintext  = b''
        ciphertext = Bytes.wrap(ciphertext)

        last_block = self.iv

        for block in get_blocks(ciphertext, self.cipher.block_size, allow_partials=True):
            enc_block  = self.cipher.encrypt(bytes(last_block))[:len(block)] ^ block
            plaintext += enc_block
            last_block = block

        return plaintext
