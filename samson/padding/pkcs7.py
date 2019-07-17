from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import InvalidPaddingException

class PKCS7(object):
    """
    PCKS#7 block cipher padding
    """

    def __init__(self, block_size: int=16):
        """
        Parameters:
            block_size (int): Block size of the cipher.
        """
        self.block_size = block_size


    def __repr__(self):
        return f"<PKCS7: block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    def pad(self, plaintext: bytes) -> Bytes:
        """
        Pads the plaintext.

        Parameters:
            plaintext (bytes): Plaintext to pad.
        
        Returns:
            Bytes: Padded plaintext.
        """
        padding = self.block_size - len(plaintext) % self.block_size
        return plaintext + Bytes(padding).stretch(padding)



    def unpad(self, plaintext: bytes) -> Bytes:
        """
        Unpads the plaintext.

        Parameters:
            plaintext (bytes): Plaintext to unpad.
        
        Returns:
            Bytes: Unpadded plaintext.
        """
        last_block = plaintext[-self.block_size:]
        last_byte = last_block[-1]

        original_text, padding = plaintext[:len(plaintext) - last_byte], last_block[-last_byte:]
        if len(padding) != last_byte or sum([last_byte != pad_char for pad_char in padding]) != 0:
            raise InvalidPaddingException('Invalid padding ;)')

        return original_text
