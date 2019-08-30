from samson.utilities.bytes import Bytes
import math

class PackedBytes(object):
    """
    Packs bytes-coercible objects into length-encoded bytes.
    """

    def __init__(self, name: str, endianness: str='big'):
        """
        Parameters:
            name (str): Name for bookkeeping purposes.
        """
        self.name = name
        self.endianness = endianness



    def __repr__(self):
        return f"<PackedBytes: name={self.name}>"

    def __str__(self):
        return self.__repr__()


    def pack(self, value: bytes, force_pack: bool=False) -> Bytes:
        """
        Packs bytes-coercible objects into length-encoded bytes.

        Parameters:
            value     (bytes): Value to encode.
            force_pack (bool): Whether or not to pack zero-length values.
        
        Returns:
            bytes: Packed bytes.
        """
        val = Bytes.wrap(value, byteorder=self.endianness)

        if issubclass(type(value), int):
            val = val.zfill(math.ceil((value.bit_length() + 1) / 8))

        if len(val) > 0 or force_pack:
            length = Bytes(len(val)).zfill(4)
        else:
            length = b''

        return length  + val


    def unpack(self, encoded_bytes: bytes) -> (bytes, bytes):
        """
        Unpacks bytes into their raw form.

        Parameters:
            encoded_bytes (bytes): Bytes to be (partially?) decoded.
        
        Returns:
            (bytes, bytes): The unpacked bytes and unused bytes.
        """
        length = encoded_bytes[:4].int()
        unpacked = encoded_bytes[4:length + 4]
        unpacked.byteorder = self.endianness
        return unpacked, encoded_bytes[length + 4:]
