from samson.block_ciphers.des import DES
from samson.utilities.bytes import Bytes
from samson.core.primitives import BlockCipher, Primitive
from samson.core.metadata import SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive

@register_primitive()
class TDES(BlockCipher):
    """
    3DES in EDE mode.

    Structure: Feistel Network
    Key size: 64, 128, 192 bits (56, 80, 112 bits of security)
    Block size: 64 bits
    """

    KEY_SIZE        = SizeSpec(size_type=SizeType.RANGE, sizes=[64, 128, 192], typical=[128, 192])
    BLOCK_SIZE      = SizeSpec(size_type=SizeType.SINGLE, sizes=64)
    USAGE_FREQUENCY = FrequencyType.NORMAL


    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Bytes-like object to key the cipher.
        """
        Primitive.__init__(self)

        key = Bytes.wrap(key)
        if not len(key) in [8, 16, 24]:
            raise ValueError('`key` size must be in [8, 16, 24]')

        self.key = key
        self.des_arr = [DES(subkey.zfill(8)) for subkey in key.chunk(8)]
        self.block_size = 8


    def __reprdir__(self):
        return ['key', 'des_arr']


    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)
        pt_1 = self.des_arr[0].encrypt(plaintext)
        pt_2 = self.des_arr[1].decrypt(pt_1)
        ciphertext = self.des_arr[2].encrypt(pt_2)

        return ciphertext


    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)
        ct_1 = self.des_arr[2].decrypt(ciphertext)
        ct_2 = self.des_arr[1].encrypt(ct_1)
        plaintext = self.des_arr[0].decrypt(ct_2)

        return plaintext
