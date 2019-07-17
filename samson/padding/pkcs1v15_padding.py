from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import InvalidPaddingException
import math

# https://tools.ietf.org/html/rfc8017#section-7.2.1
class PKCS1v15Padding(object):
    """
    PCKS#1 v1.5 RSA padding
    """

    def __init__(self, key_bit_length: int, block_type: int=2):
        """
        Parameters:
            key_bit_length (int): Length of the RSA modulus in bits.
        """
        self.key_byte_length = math.ceil(key_bit_length / 8)
        self.block_type = block_type


    def __repr__(self):
        return f"<PKCS1v15Padding: key_byte_length={self.key_byte_length}>"

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
        block_type = bytes([self.block_type])
        pad_len = self.key_byte_length - 3 - len(plaintext)
        assert pad_len >= 8

        if self.block_type == 0:
            padding = Bytes(b'').zfill(pad_len)

        elif self.block_type == 1:
            padding = Bytes(b'\xff').stretch(pad_len)

        elif self.block_type == 2:
            padding = Bytes.random(pad_len) | Bytes(0x01).stretch(pad_len)

        return b'\x00' + block_type + padding + b'\x00' + plaintext



    def unpad(self, plaintext: bytes, allow_padding_oracle: bool=False) -> Bytes:
        """
        Unpads the plaintext.

        Parameters:
            plaintext           (bytes): Plaintext to unpad.
            allow_padding_oracle (bool): Whether or not to explicitly create a padding oracle.
        
        Returns:
            Bytes: Unpadded plaintext.
        """
        if allow_padding_oracle and (plaintext[:2] != b'\x00\x02' or len(plaintext) != self.key_byte_length):
            raise InvalidPaddingException('Invalid padding ;)')

        header_removed = plaintext[2:]
        first_zero = header_removed.index(b'\x00')
        data_idx = first_zero

        if self.block_type == 0:
            while not header_removed[data_idx + 1]:
                data_idx += 1

        return header_removed[data_idx + 1:]
