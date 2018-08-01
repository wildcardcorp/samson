from math import ceil, log
from scipy.stats import chisquare
import struct
from Crypto import Random
import zlib

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



def get_blocks(cipher, block_size=16, allow_partials=False):
    full_blocks = [cipher[i * block_size: (i + 1) * block_size] for i in range(len(cipher) // block_size)]

    left_over = len(cipher) % block_size

    if allow_partials and left_over > 0:
        all_blocks = full_blocks + [cipher[-left_over:]]
    else:
        all_blocks = full_blocks
    return all_blocks


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
    padding = gen_rand_key(key_byte_length - 3 - len(data))
    return b'\x00\x02' + padding + b'\x00' + data


def count_bytes(in_bytes):
    byte_ctr = {curr_byte: 0 for curr_byte in in_bytes}
    for curr_byte in in_bytes:
        byte_ctr[curr_byte] += 1

    return byte_ctr


def int_to_bytes(n, byteorder='little'):
    """Converts the given int n to bytes and returns them."""
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder)



def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)



def lcm(a, b):
    return a // gcd(a, b) * b


def mod_inv(a, n):
    """
    Calculates the modular inverse according to
    https://en.wikipedia.org/wiki/Euclidean_algorithm#Linear_Diophantine_equations
    and https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """

    t = 0
    r = n

    new_t = 1
    new_r = a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    
    if r > 1:
        raise Exception("'a' is not invertible")
    
    if t < 0:
        t = t + n

    return t
    

# # Simple and naive way to tell. Obviously can't work all the time.
# def is_stateless_function(ciphertext):
#     length = len(ciphertext)
#     chi_cipher = calculate_byte_distribution(ciphertext)
#     chi_reference = calculate_byte_distribution(b'\x00' * length)

#     reference_ratio = log(chi_cipher.statistic) / log(chi_reference.statistic)

#     compressed = zlib.compress(ciphertext)
#     return (len(compressed) < length, chi_cipher, reference_ratio)
    

def modexp (g, u, p):
   """computes s = (g ^ u) mod p
      args are base, exponent, modulus
      (see Bruce Schneier's book, _Applied Cryptography_ p. 244)"""
   s = 1
   while u != 0:
      if u & 1:
         s = (s * g)%p
      u >>= 1
      g = (g * g)%p
   return s



def calculate_byte_distribution(in_bytes):
    byte_ctrs = count_bytes(in_bytes)
    results = [v for k,v in byte_ctrs.items()]

    padded_results = [0] * (min(len(in_bytes) - len(results), 256 - len(results))) + results
    
    return chisquare(padded_results)


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
