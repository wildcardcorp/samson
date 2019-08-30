from samson.utilities.bytes import Bytes

class Literal(object):
    """
    A value to be taken literally (no formatting).
    """

    def __init__(self, name: str, length: int=4):
        """
        Parameters:
            name   (str): Name for bookkeeping purposes.
            length (int): Length to be packed into (zfilled).
        """
        self.name = name
        self.length = length


    def __repr__(self):
        return f"<Literal: name={self.name}, length={self.length}>"

    def __str__(self):
        return self.__repr__()


    def pack(self, value: bytes) -> Bytes:
        """
        Packs a bytes-coercible value into its encoded form.

        Parameters:
            value (bytes): Value to be encoded.
        
        Returns:
            Bytes: Encoded value.
        """
        val = Bytes.wrap(value)
        if len(val) > 0:
            val = val.zfill(self.length)
        else:
            val = b''
        return val


    def unpack(self, encoded_bytes: bytes) -> (bytes, bytes):
        """
        Unpacks bytes into it's literal form.

        Parameters:
            encoded_bytes (bytes): Bytes to be (partially?) decoded.
        
        Returns:
            (bytes, bytes): The unpacked literal and unused bytes.
        """
        return encoded_bytes[:self.length], encoded_bytes[self.length:]
