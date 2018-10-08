from math import ceil

def xor_buffs(buf1, buf2):
    if len(buf1) != len(buf2):
        raise Exception('Buffers must be equal length.')

    return bytearray([x ^ y for x, y in zip(buf1, buf2)])



# Stretches a `key` into a stream of `length`. Key can be shifted by `offset`.

# Examples
# >>> stretch_key(b'abc', 5)
# b'abcab'

# >>> stretch_key(b'abc', 5, offset=1)
# b'cabca'

def stretch_key(key, length, offset=0):
    offset_mod = offset % len(key)
    key_stream = (key * ceil(length / len(key)))
    complete_key = (key[-offset_mod:] + key_stream)[:length]
    return complete_key



def transpose(cipherbytes, key_size):
    return [cipherbytes[i::key_size] for i in range(key_size)]


def get_blocks(cipher, block_size=16, allow_partials=False):
    full_blocks = [cipher[i * block_size: (i + 1) * block_size] for i in range(len(cipher) // block_size)]

    left_over = len(cipher) % block_size

    if allow_partials and left_over > 0:
        all_blocks = full_blocks + [cipher[-left_over:]]
    else:
        all_blocks = full_blocks
    return all_blocks


def left_rotate(x, amount, bits=32):
    mask = 2 ** bits - 1
    x &= mask
    return ((x<<amount) | (x>>(bits-amount))) & mask


def right_rotate(x, amount, bits=32):
    mask = 2 ** bits - 1
    return ((x>>amount) | (x<<(bits-amount))) & mask