from samson.utilities.manipulation import get_blocks, transpose, stretch_key
from samson.utilities.general import rand_bytes
from samson.utilities.bytes import Bytes
import math
from collections import UserString

def _zfill(bs, size, byteorder):
    zeroes = max(size - len(bs), 0) * '0'
    if byteorder == 'big':
        new_bitstring = zeroes + bs
    else:
        new_bitstring = bs + zeroes

    return new_bitstring


class Bitstring(UserString):
    """
    Bitvector manipulation class. Supports popular manipulations such as XOR, stretching, chunking, transposing, and rotations.
    Manipulations always return a new Bitstring instance instead of editing the old one.
    """

    def __init__(self, value: bytes, byteorder: str='big', auto_fill: bool=True):
        """
        Parameters:
            value    (bytes): Bytes, integer, or string of 1s and 0s.
            byteorder  (str): Byteorder for integer and byte conversions.
            auto_fill (bool): Whether or not to automatically zero fill to the next byte.
        """
        if type(value) is bytes or type(value) is bytearray or type(value) is Bytes:
            value = int.from_bytes(value, byteorder)

        if type(value) is int:
            value = bin(value)[2:]
            if auto_fill:
                value = _zfill(value, math.ceil(len(value) / 8) * 8, byteorder)


        if not all([bit in ['0', '1'] for bit in str(value)]):
            raise Exception("Bitstrings can only contain 1's or 0's.")

        super().__init__(value)
        self.byteorder = byteorder
        self.auto_fill = auto_fill


    def _format_return(self, value: bytes):
        """
        Internal function. Used to reformat the Bitstring after manipulations for ease of use.
        """
        return Bitstring(str(Bitstring(value, 'big', auto_fill=self.auto_fill).zfill(len(self))), self.byteorder, auto_fill=self.auto_fill)


    @staticmethod
    def wrap(value: bytes, byteorder: str='big', auto_fill: bool=True):
        """
        Conditional initialization. Only creates a new Bitstring object if it already isn't one.

        Parameters:
            value    (bytes): Bytes, integer, or string of 1s and 0s.
            byteorder  (str): Byteorder for integer and byte conversions.
            auto_fill (bool): Whether or not to automatically zero fill to the next byte.
        
        Returns:
            Bitstring: A Bitstring representation of the object.
        """
        if isinstance(value, Bitstring):
            return value
        else:
            return Bitstring(value, byteorder=byteorder, auto_fill=auto_fill)


    @staticmethod
    def random(size: int=16, byteorder: str='big'):
        """
        Generates a random Bitstring object using /dev/urandom.

        Parameters:
            size      (int): Number of bytes to generate.
            byteorder (int): Byteorder.
        
        Returns:
            Bitstring: Random Bitstring.
        """
        return Bitstring(rand_bytes(math.ceil(size / 8)), byteorder=byteorder)[:size]


    def __repr__(self):
        return f'<Bitstring: {" ".join([str(chunk) for chunk in self.zfill(math.ceil(max(1, len(self)) / 8) * 8).chunk(8)])}, byteorder={self.byteorder}>'


    # Byte order will be the downfall of humanity.
    def _clean_byteorder(self, value):
        value.byteorder = 'big'
        return value.int()



    def __xor__(self, other):
        other = Bitstring.wrap(other, self.byteorder, auto_fill=self.auto_fill).bytes()
        result = self._clean_byteorder(self.bytes() ^ other)
        return self._format_return(result)


    def __rxor__(self, other):
        return self.__xor__(other)


    def __getitem__(self, index):
        return Bitstring(UserString.__getitem__(self, index), self.byteorder)


    def __and__(self, other):
        other = Bitstring.wrap(other, self.byteorder, auto_fill=self.auto_fill).bytes()
        result = self._clean_byteorder(self.bytes() & other)
        return self._format_return(result)


    def __rand__(self, other):
        return self.__and__(other)


    def __or__(self, other):
        other = Bitstring.wrap(other, self.byteorder, auto_fill=self.auto_fill).bytes()
        result = self._clean_byteorder(self.bytes() | other)
        return self._format_return(result)


    def __ror__(self, other):
        return self.__or__(other)


    def __add__(self, other):
        return Bitstring(UserString.__add__(self, other), self.byteorder, auto_fill=self.auto_fill)


    def __radd__(self, other):
        return Bitstring(UserString(other).__add__(self), self.byteorder, auto_fill=self.auto_fill)


    def __lshift__(self, num):
        return self._format_return(self.bytes() << num)


    def __rshift__(self, num):
        return self._format_return(self.bytes() >> num)


    def __invert__(self):
        max_val = 2 ** len(self) - 1
        return self._format_return(max_val - self.int())


    def lrot(self, amount: int, bits: int=None):
        """
        Performs a left-rotate.

        Parameters:
            amount (int): Amount to rotate by.
            bits   (int): Bitspace to rotate over.
        
        Returns:
            Bitstring: A new instance of Bitstring with the transformation applied.
        """
        return self._format_return(self.bytes().lrot(amount, bits=bits))


    def rrot(self, amount: int, bits: int=None):
        """
        Performs a right-rotate.

        Parameters:
            amount (int): Amount to rotate by.
            bits   (int): Bitspace to rotate over.
        
        Returns:
            Bitstring: A new instance of Bitstring with the transformation applied.
        """
        return self._format_return(self.bytes().rrot(amount, bits=bits))


    def chunk(self, size: int, allow_partials: bool=False) -> list:
        """
        Chunks the Bitstring into `size` length chunks.

        Parameters:
            size            (int): Size of the chunks.
            allow_partials (bool): Whether or not to allow the last chunk to be a partial.
        
        Returns:
            list: List of Bitstrings.
        """
        return get_blocks(self, size, allow_partials)


    def transpose(self, size: int):
        """
        Builds a matrix of `size` row-length, transposes the matrix, and collapses it back into a Bitstring object.

        Parameters:
            size (int): Length of the rows/chunks.
        
        Returns:
            Bitstring: Transposed bits.
        """
        return self._format_return(''.join(transpose(str(self), size)))


    def zfill(self, size: int):
        """
        Fills the Bitstring to specified size with 0 bits _such that the integer representation stays the same according to the byteorder_.

        Parameters:
            size (int): Size of the resulting Bitstring.
        
        Return:
            Bitstring: Bitstring padded with zeroes.
        """
        return _zfill(self, size, self.byteorder)


    def stretch(self, size: int, offset: int=0):
        """
        Repeats a Bitstring object until it reaches `size` length shifted by `offset`.

        Examples:

        >>> stretch_key(b'abc', 5)
        b'abcab'

        >>> stretch_key(b'abc', 5, offset=1)
        b'cabca'


        Parameters:
            size   (int): Size to be stretched to.
            offset (int): Offset to start from.
        
        Returns:
            Bitstring: Bitstring stretched to `size`.
        """
        return self._format_return(stretch_key(self, size, offset))


    def to_int(self) -> int:
        """
        Converts to an integer representation.

        Returns:
            int: Integer representation.
        """
        return self.bytes().int()


    def int(self) -> int:
        """
        Converts to an integer representation.

        Returns:
            int: Integer representation.
        """
        return self.to_int()


    def to_bytes(self):
        """
        Converts to a Bytes representation.

        Returns:
            Bytes: Bytes representation.
        """
        return Bytes([int(str(chunk), 2) for chunk in self.zfill(self.byte_length()).chunk(8, allow_partials=True)], self.byteorder)


    def bytes(self):
        """
        Converts to a Bytes representation.

        Returns:
            Bytes: Bytes representation.
        """
        return self.to_bytes()


    def byte_length(self) -> int:
        """
        The Bitstrings length to the nearest byte.

        Returns:
            int: The Bitstring's byte-length.
        """
        return math.ceil(len(self) / 8)
