from math import ceil
import struct
from Crypto import Random

rndfile = Random.new()

def gen_rand_key(size=16):
    return rndfile.read(size)
    

def byte_to_bitstring(input_bytes, fill=8):
    return ''.join(format(x, 'b').zfill(fill) for x in input_bytes)



def xor_buffs(buf1, buf2):
    if len(buf1) != len(buf2):
        raise Exception('Buffers must be equal length.')

    return bytearray([x ^ y for x, y in zip(buf1, buf2)])



def stretch_key(key, length):
    return (key * ceil(length / len(key)))[:length]



def hamming_distance(bytes1, bytes2):
    assert len(bytes1) == len(bytes2)
    bitstring1 = byte_to_bitstring(bytes1)
    bitstring2 = byte_to_bitstring(bytes2)

    distance = 0
    for bit1, bit2 in zip(bitstring1, bitstring2):
        if bit1 != bit2: distance += 1

    return distance


def transpose(cipherbytes, key_size):
    return [cipherbytes[i::key_size] for i in range(key_size)]



def get_blocks(cipher, block_size=16):
    return [cipher[i * block_size: (i + 1) * block_size] for i in range(len(cipher) // block_size)]


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


def de_bruijn(k, n):
  """
  de Bruijn sequence for alphabet k
  and subsequences of length n.
  """
  try:
      # let's see if k can be cast to an integer;
      # if so, make our alphabet a list
      _ = int(k)
      alphabet = list(map(str, range(k)))

  except (ValueError, TypeError):
      alphabet = k
      k = len(k)

  a = [0] * k * n
  sequence = []

  def db(t, p):
      if t > n:
          if n % p == 0:
              sequence.extend(a[1:p + 1])
      else:
          a[t] = a[t - p]
          db(t + 1, p)
          for j in range(a[t - p] + 1, k):
              a[t] = j
              db(t + 1, t)
  db(1, 1)
  return "".join(alphabet[i] for i in sequence)
