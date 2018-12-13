from samson.utilities.bytes import Bytes
import math

# https://tools.ietf.org/html/rfc8017#section-7.2.1
class PKCS1v15(object):
    """
    PCKS#1 v1.5 RSA padding
    """

    def __init__(self, key_bit_length: int):
        """
        Parameters:
            key_bit_length (int): Length of the RSA modulus in bits.
        """
        self.key_byte_length = math.ceil(key_bit_length / 8)


    def __repr__(self):
        return f"<PKCS1v15: key_byte_length={self.key_byte_length}>"

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
        pad_len = self.key_byte_length - 3 - len(plaintext)
        assert pad_len >= 8

        padding = Bytes.random(pad_len) | Bytes(0x01).stretch(pad_len)
        return b'\x00\x02' + padding + b'\x00' + plaintext



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
            raise Exception('Invalid padding ;)')

        header_removed = plaintext[2:]
        return header_removed[header_removed.index(b'\x00') + 1:]
