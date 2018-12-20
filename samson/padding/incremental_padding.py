from samson.utilities.bytes import Bytes

class IncrementalPadding(object):
    """
    Incremental padding. Used in OpenSSH's keys.
    """

    def __init__(self, block_size: int=8):
        """
        Parameters:
            block_size (int): Block size to pad to.
        """
        self.block_size = block_size


    def __repr__(self):
        return f"<IncrementalPadding: block_size={self.block_size}>"

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
        return plaintext + Bytes([_ for _ in range(1, padding + 1)])



    def unpad(self, plaintext: bytes) -> Bytes:
        """
        Unpads the plaintext.

        Parameters:
            plaintext           (bytes): Plaintext to unpad.
        
        Returns:
            Bytes: Unpadded plaintext.
        """
        return plaintext[:-plaintext[-1]]
