from samson.block_ciphers.modes.cbc import CBC
from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael
from samson.core.primitives import MAC, Primitive, EncryptionAlg
from samson.core.metadata import FrequencyType
from samson.ace.decorators import register_primitive

@register_primitive()
class CBCMAC(MAC):
    """
    Message authentication code scheme based off of a block cipher in CBC mode.
    """

    USAGE_FREQUENCY = FrequencyType.NORMAL

    def __init__(self, cipher: EncryptionAlg=None, iv: bytes=b'\x00' * 16):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Initialization vector for CBC mode.
        """
        Primitive.__init__(self)
        self.cbc = CBC(cipher or Rijndael(Bytes.random(32)), iv)


    def __reprdir__(self):
        return ['cbc']


    def generate(self, message: bytes, pad: bool=True) -> Bytes:
        """
        Generates a keyed MAC for `message`.

        Parameters:
            message (bytes): Message to generate a MAC for.
            pad      (bool): Whether or not to pad the message with PKCS7.
        
        Returns:
            Bytes: The MAC.
        """
        return self.cbc.encrypt(Bytes.wrap(message), pad)[-(self.cbc.cipher.block_size):]
