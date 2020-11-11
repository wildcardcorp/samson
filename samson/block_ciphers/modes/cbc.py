from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from samson.padding.pkcs7 import PKCS7
from samson.ace.decorators import has_exploit, register_primitive
from samson.attacks.cbc_padding_oracle_attack import CBCPaddingOracleAttack
from samson.core.primitives import EncryptionAlg, BlockCipherMode, Primitive
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec, FrequencyType

@has_exploit(CBCPaddingOracleAttack)
@register_primitive()
class CBC(BlockCipherMode):
    """Cipherblock chaining block cipher mode."""

    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.IV, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE))
    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, cipher: EncryptionAlg, iv: bytes):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Bytes-like initialization vector.
        """
        Primitive.__init__(self)
        self.cipher = cipher
        self.iv     = iv
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


        if len(plaintext) % self.cipher.block_size != 0:
            raise ValueError("Plaintext is not a multiple of the block size")

        ciphertext = Bytes(b'')
        last_block = self.iv

        for block in get_blocks(plaintext, self.cipher.block_size):
            enc_block = self.cipher.encrypt(bytes(last_block ^ block))
            ciphertext += enc_block
            last_block = enc_block

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
        plaintext  = b''
        ciphertext = Bytes.wrap(ciphertext)

        self.check_ciphertext_length(ciphertext)

        last_block = self.iv
        for block in get_blocks(ciphertext, self.cipher.block_size):
            enc_block = last_block ^ Bytes.wrap(self.cipher.decrypt(block))
            plaintext += enc_block
            last_block = block

        if unpad:
            plaintext = self.padder.unpad(plaintext)

        return plaintext
