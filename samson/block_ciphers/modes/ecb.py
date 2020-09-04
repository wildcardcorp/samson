from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from samson.padding.pkcs7 import PKCS7
from samson.core.primitives import EncryptionAlg, BlockCipherMode, Primitive
from samson.ace.decorators import register_primitive

@register_primitive()
class ECB(BlockCipherMode):
    """Electronic codebook block cipher mode."""

    def __init__(self, cipher: EncryptionAlg):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
        """
        Primitive.__init__(self)
        self.cipher = cipher
        self.padder = PKCS7(self.cipher.block_size)



    def encrypt(self, plaintext: bytes, pad: bool=True) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
            pad        (bool): Pads the plaintext with PKCS7.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)

        if pad:
            plaintext = self.padder.pad(plaintext)

        ciphertext = Bytes(b'')
        for block in get_blocks(plaintext, self.cipher.block_size):
            ciphertext += self.cipher.encrypt(block)

        return ciphertext



    def decrypt(self, ciphertext: bytes, unpad: bool=True) -> Bytes:
        """
        Decrypts `ciphertext`.
        
        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
            unpad       (bool): Unpads the plaintext with PKCS7.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)

        self.check_ciphertext_length(ciphertext)

        plaintext = Bytes(b'')
        for block in get_blocks(ciphertext, self.cipher.block_size):
            plaintext += self.cipher.decrypt(block)

        if unpad:
            plaintext = self.padder.unpad(plaintext)

        return plaintext
