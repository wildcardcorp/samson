import struct
from samson.utilities.general import rand_bytes

def pkcs7_pad(text, block_size=16):
    padding = block_size - len(text) % block_size
    return text + struct.pack('B', padding) * padding


def pkcs7_unpad(text, block_size=16):
    last_block = text[-block_size:]
    last_byte = last_block[-1]

    original_text, padding = text[:len(text) - last_byte], last_block[-last_byte:]
    if len(padding) != last_byte or sum([last_byte != pad_char for pad_char in padding]) != 0:
        raise Exception('Invalid padding ;)')

    return original_text


def pkcs15_pad(data, key_byte_length):
    padding = rand_bytes(key_byte_length - 3 - len(data))
    return b'\x00\x02' + padding + b'\x00' + data


def md_pad(msg, fakeLen=None, byteorder='little'):
    length = fakeLen or len(msg)
    # append the bit '1' to the message
    padding = b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    padding += b'\x00' * ((56 - (length + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message_bit_length = length * 8
    #padding += int_to_bytes(message_bit_length, endian)
    padding += message_bit_length.to_bytes(8, byteorder=byteorder)
    #padding += struct.pack(b'>Q', message_bit_length)
    return msg + padding

    