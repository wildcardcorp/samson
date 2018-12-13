from samson.utilities.manipulation import xor_buffs, left_rotate, right_rotate, get_blocks, transpose, stretch_key
from samson.utilities.encoding import int_to_bytes
from samson.utilities.general import rand_bytes
import codecs

class Bytes(bytearray):
    """
    Bytearray convenience class. Supports popular manipulations such as XOR, stretching, chunking, transposing, and rotations.
    Manipulations always return a new Bytes instance instead of editing the old one.
    """

    def __init__(self, bytes_like: bytes, byteorder: str='big'):
        """
        Parameters:
            bytes_like (bytes): Any bytes-like interface or integer. Integers will be converted using the byteorder.
            byteorder    (str): Byte order of the input. Will be used when converting between integer and byte representations.
        """
        if type(bytes_like) is int:
            bytes_like = int_to_bytes(bytes_like, byteorder)

        super().__init__(bytes_like)
        self.byteorder = byteorder


    @staticmethod
    def wrap(bytes_like: bytes, byteorder: str='big'):
        """
        Conditional initialization. Only creates a new Bytes object if it already isn't one.

        Parameters:
            bytes_like (bytes): Any bytes-like interface or integer. Integers will be converted using the byteorder.
            byteorder    (str): Byte order of the input. Will be used when converting between integer and byte representations.
        
        Returns:
            Bytes: A Bytes representation of the object.
        """
        if isinstance(bytes_like, Bytes):
            return bytes_like
        else:
            return Bytes(bytes_like, byteorder=byteorder)


    @staticmethod
    def random(size: int=16, byteorder: str='big'):
        """
        Generates a random Bytes object using /dev/urandom.

        Parameters:
            size      (int): Number of bytes to generate.
            byteorder (int): Byteorder.
        
        Returns:
            Bytes: Random Bytes.
        """
        return Bytes(rand_bytes(size), byteorder=byteorder)



    def __repr__(self):
        return f'<Bytes: {str(bytes(self))}, byteorder={self.byteorder}>'

    def __str__(self):
        return self.__repr__()


    # Operators
    def __xor__(self, other):
        if type(other) is int:
            return Bytes(int.to_bytes(self.to_int() ^ other, len(self), self.byteorder), self.byteorder)
        else:
            return Bytes(xor_buffs(self, other), self.byteorder)


    def __rxor__(self, other):
        return self.__xor__(other)


    def __getitem__(self, index):
        result = bytearray.__getitem__(self, index)
        if type(result) is int:
            return result
        else:
            return Bytes(result, self.byteorder)


    def __and__(self, other):
        other_as_int = other

        if not type(other) is int:
            other_as_int = int.from_bytes(other, self.byteorder)

        return Bytes(int.to_bytes(self.to_int() & other_as_int, len(self), self.byteorder), self.byteorder)


    def __rand__(self, other):
        return self.__and__(other)


    def __or__(self, other):
        other_as_int = other

        if not type(other) is int:
            other_as_int = int.from_bytes(other, self.byteorder)

        return Bytes(int.to_bytes(self.to_int() | other_as_int, len(self), self.byteorder), self.byteorder)


    def __ror__(self, other):
        return self.__or__(other)


    def __add__(self, other):
        return Bytes(bytearray.__add__(self, other), self.byteorder)


    def __radd__(self, other):
        return Bytes(bytearray(other).__add__(self), self.byteorder)


    def __lshift__(self, num):
        return Bytes(int.to_bytes((self.to_int() << num) %  (2**(len(self) * 8)), len(self), self.byteorder))


    def __rshift__(self, num):
        return Bytes(int.to_bytes((self.to_int() >> num) % (2**(len(self) * 8)), len(self), self.byteorder))


    def __invert__(self):
        max_val = 2 ** (len(self) * 8) - 1
        return Bytes(max_val - self.to_int(), self.byteorder)


    # Manipulations
    def lrot(self, amount: int, bits: int=None):
        """
        Performs a left-rotate.

        Parameters:
            amount (int): Amount to rotate by.
            bits   (int): Bitspace to rotate over.
        
        Returns:
            Bytes: A new instance of Bytes with the transformation applied.
        """
        if not bits:
            bits = len(self) * 8

        back_to_bytes = int.to_bytes(left_rotate(self.to_int(), amount, bits), bits // 8, self.byteorder)
        return Bytes(back_to_bytes, self.byteorder)



    def rrot(self, amount: int, bits: int=None):
        """
        Performs a right-rotate.

        Parameters:
            amount (int): Amount to rotate by.
            bits   (int): Bitspace to rotate over.
        
        Returns:
            Bytes: A new instance of Bytes with the transformation applied.
        """
        if not bits:
            bits = len(self) * 8

        back_to_bytes = int.to_bytes(right_rotate(self.to_int(), amount, bits), bits // 8, self.byteorder)
        return Bytes(back_to_bytes, self.byteorder)



    def chunk(self, size: int, allow_partials: bool=False) -> list:
        """
        Chunks the Bytes into `size` length chunks.

        Parameters:
            size            (int): Size of the chunks.
            allow_partials (bool): Whether or not to allow the last chunk to be a partial.
        
        Returns:
            list: List of Bytes.
        """
        return get_blocks(self, size, allow_partials)



    def transpose(self, size: int):
        """
        Builds a matrix of `size` row-length, transposes the matrix, and collapses it back into a Bytes object.

        Parameters:
            size (int): Length of the rows/chunks.
        
        Returns:
            Bytes: Transposed bytes.
        """
        return Bytes(b''.join(transpose(self, size)), self.byteorder)



    def zfill(self, size: int):
        """
        Fills the Bytes to specified size with NUL bytes _such that the integer representation stays the same according to the byteorder_.

        Parameters:
            size (int): Size of the resulting Bytes.
        
        Return:
            Bytes: Bytes padded with zeroes.
        """
        return Bytes(int.to_bytes(self.to_int(), size, self.byteorder), self.byteorder)



    def stretch(self, size: int, offset: int=0):
        """
        Repeats a Bytes object until it reaches `size` length shifted by `offset`.

        Examples:

        >>> stretch_key(b'abc', 5)
        b'abcab'

        >>> stretch_key(b'abc', 5, offset=1)
        b'cabca'


        Parameters:
            size   (int): Size to be stretched to.
            offset (int): Offset to start from.
        
        Returns:
            Bytes: Bytes stretched to `size`.
        """
        return Bytes(stretch_key(self, size, offset), self.byteorder)



    # Conversions
    def to_int(self) -> int:
        """
        Converts to an integer representation.

        Returns:
            int: Integer representation.
        """
        return int.from_bytes(self, self.byteorder)


    def int(self) -> int:
        """
        Converts to an integer representation.

        Returns:
            int: Integer representation.
        """
        return self.to_int()


    def to_hex(self):
        """
        Converts to an hex representation.

        Returns:
            Bytes: Hex representation.
        """
        return Bytes(codecs.encode(self, 'hex_codec'), self.byteorder)


    def hex(self):
        """
        Converts to an hex representation.
        
        Returns:
            Bytes: Hex representation.
        """
        return self.to_hex()


    def unhex(self):
        """
        Converts from an hex representation.

        Returns:
            Bytes: Raw bytes representation.
        """
        return Bytes(codecs.decode(self, 'hex_codec'), self.byteorder)


    def to_bin(self):
        """
        Converts to a Bitstring representation.

        Returns:
            Bitstring: Bitstring representation.
        """
        from samson.utilities.bitstring import Bitstring
        return Bitstring(self, byteorder=self.byteorder).zfill(len(self) * 8)


    def bin(self):
        """
        Converts to a Bitstring representation.

        Returns:
            Bitstring: Bitstring representation.
        """
        return self.to_bin()


    def to_bits(self):
        """
        Converts to a Bitstring representation.

        Returns:
            Bitstring: Bitstring representation.
        """
        return self.to_bin()


    def bits(self):
        """
        Converts to a Bitstring representation.

        Returns:
            Bitstring: Bitstring representation.
        """
        return self.to_bits()
