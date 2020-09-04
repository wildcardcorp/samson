from samson.utilities.bytes import Bytes
from samson.core.primitives import EncryptionAlg, StreamingBlockCipherMode, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive
from math import ceil

@register_primitive()
class CTR(StreamingBlockCipherMode):
    """Counter block cipher mode."""

    # TODO: This nonce is a RANGE that is DEPENDENT on BLOCK_SIZE
    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE, typical=[96]))
    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, cipher: EncryptionAlg, nonce: bytes):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            nonce          (bytes): Bytes-like nonce.
        """
        Primitive.__init__(self)
        self.cipher    = cipher
        self.nonce     = Bytes.wrap(nonce)
        self.counter   = 0
        self.byteorder = self.nonce.byteorder



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        keystream = Bytes(b'')
        plaintext = Bytes.wrap(plaintext)

        num_blocks = ceil(len(plaintext) / self.cipher.block_size)
        for _ in range(num_blocks):
            keystream += self.cipher.encrypt(self.nonce + self.counter.to_bytes(self.cipher.block_size - len(self.nonce), self.byteorder))
            self.counter += 1

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
