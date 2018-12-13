from math import ceil

def xor_buffs(buf1: bytes, buf2: bytes) -> bytearray:
    """
    XORs two byte buffers.

    Parameters:
        buf1 (bytes): First byte buffer.
        buf2 (bytes): Second byte buffer.
    
    Returns:
        bytearray: Resulting bytes.
    """
    if len(buf1) != len(buf2):
        raise Exception('Buffers must be equal length.')

    return bytearray([x ^ y for x, y in zip(buf1, buf2)])



def stretch_key(key: bytes, length: int, offset: int=0) -> bytes:
    """
    Repeats a bytes object until it reaches `size` length shifted by `offset`.

    Examples:

    >>> stretch_key(b'abc', 5)
    b'abcab'

    >>> stretch_key(b'abc', 5, offset=1)
    b'cabca'


    Parameters:
        size   (int): Size to be stretched to.
        offset (int): Offset to start from.
    
    Returns:
        bytes: Bytes stretched to `size`.
    """
    offset_mod = offset % len(key)
    key_stream = (key * ceil(length / len(key)))
    complete_key = (key[-offset_mod:] + key_stream)[:length]
    return complete_key



def transpose(ciphertext: bytes, size: int) -> bytes:
    """
    Builds a matrix of `size` row-length, transposes the matrix, and collapses it back into a bytes object.

    Parameters:
        size (int): Length of the rows/chunks.
    
    Returns:
        bytes: Transposed bytes.
    """
    return [ciphertext[i::size] for i in range(size)]



def get_blocks(ciphertext: bytes, block_size: int=16, allow_partials: bool=False) -> list:
    """
    Chunks the bytes into `size` length chunks.

    Parameters:
        size            (int): Size of the chunks.
        allow_partials (bool): Whether or not to allow the last chunk to be a partial.
    
    Returns:
        list: List of bytes.
    """
    full_blocks = [ciphertext[i * block_size: (i + 1) * block_size] for i in range(len(ciphertext) // block_size)]

    left_over = len(ciphertext) % block_size

    if allow_partials and left_over > 0:
        all_blocks = full_blocks + [ciphertext[-left_over:]]
    else:
        all_blocks = full_blocks
    return all_blocks



def left_rotate(x: int, amount: int, bits: int=32) -> int:
    """
    Performs a left-rotate.

    Parameters:
        x      (int): Integer to rotate.
        amount (int): Amount to rotate by.
        bits   (int): Bitspace to rotate over.
    
    Returns:
        int: Rotated integer.
    """
    mask = 2 ** bits - 1
    x &= mask
    return ((x<<amount) | (x>>(bits-amount))) & mask



def right_rotate(x: int, amount: int, bits: int=32) -> int:
    """
    Performs a right-rotate.

    Parameters:
        x      (int): Integer to rotate.
        amount (int): Amount to rotate by.
        bits   (int): Bitspace to rotate over.
    
    Returns:
        int: Rotated integer.
    """
    mask = 2 ** bits - 1
    return ((x>>amount) | (x<<(bits-amount))) & mask
