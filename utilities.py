from math import ceil, log, sqrt
from scipy.stats import chisquare
import scipy.special
import struct
from Crypto import Random
from Crypto.Cipher import ARC4
import os
import zlib
import json
import difflib

#rndfile = Random.new()
URANDOM = open("/dev/urandom", "rb")

RC4_BIAS_MAP = [163, 0, 131, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 240, 17, 18, 0, 20, 21, 22, 0, 24, 25, 26, 0, 28, 29, 0, 31, 224, 33, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 0, 0, 0]

def gen_rand_key(size=16):
    return URANDOM.read(size)
    #return rndfile.read(size)
    

def byte_to_bitstring(input_bytes, fill=8):
    return ''.join(format(x, 'b').zfill(fill) for x in input_bytes)



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


def longest_substring(strA, strB):
    seqMatch = difflib.SequenceMatcher(None, strA, strB)
    match = seqMatch.find_longest_match(0, len(strA), 0, len(strB))
    return strA[match.a: match.a + match.size]



def hamming_distance(bytes1, bytes2):
    assert len(bytes1) == len(bytes2)
    bitstring1 = byte_to_bitstring(bytes1)
    bitstring2 = byte_to_bitstring(bytes2)

    distance = 0
    for bit1, bit2 in zip(bitstring1, bitstring2):
        if bit1 != bit2: distance += 1

    return distance


def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + 1       # than s2
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


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




def birthday_attack(bits, probability):
    return sqrt(2 * 2**bits * log(1/(1-float(probability))))


def expected_collisions(bits, num_inputs):
   return 2**(-bits)*scipy.special.comb(num_inputs, 2)


def generate_rc4_bias_map(ciphertexts):
    bias_map = [{} for i in range(256)]
    for c in ciphertexts:
        for i, byte in enumerate(c):
            if byte in bias_map[i]:
                bias_map[i][byte] = bias_map[i][byte] + 1
            else:
                bias_map[i][byte] = 1

    for i,_ in enumerate(bias_map):
        bias_map[i] = sorted(bias_map[i].items(), key=lambda kv: kv[1], reverse=True)

    return bias_map



def generate_random_rc4_bias_map(data=b'\x00' * 51, key_size=128, sample_size=2**20):
    ciphertexts = []
    for _ in range(sample_size):
        key = os.urandom(key_size // 8)
        cipher = ARC4.new(key)
        ciphertexts.append(cipher.encrypt(data))


    return generate_rc4_bias_map(ciphertexts)



def incremental_rc4_bias_map_gen(filepath, start_idx=0, data=b'\x00' * 51, key_size=128, sample_size=2**30, chunk_size=2**24):
    if sample_size % chunk_size > 0:
        iteration_mod = 1
    else:
        iteration_mod = 0


    iterations = sample_size // chunk_size + iteration_mod

    for i in range(start_idx, iterations):
        if i == iterations - 1 and iteration_mod == 1:
            mod_sample_size = sample_size % chunk_size
        else:
            mod_sample_size = chunk_size
        
        bias_map = generate_random_rc4_bias_map(data, key_size, mod_sample_size)
        

        with open(filepath + ".{}".format(i), "w+") as f:
            f.write(json.dumps(bias_map))

        del bias_map



def merge_rc4_bias_map_files(base_path, num):
    bias_maps = []
    for i in range(num):
        with open("{}.{}".format(base_path, i)) as f:
            content = f.read()
        
        bias_maps.append(json.loads(content))

    return merge_rc4_bias_maps(bias_maps)



def merge_rc4_bias_maps(bias_maps):
    merged_map = [{} for i in range(256)]

    for bias_map in bias_maps:
        for i,_ in enumerate(bias_map):
            for k,v in bias_map[i]:
                if k in merged_map[i]:
                    merged_map[i][k] += v
                else:
                    merged_map[i][k] = v

    for i,_ in enumerate(merged_map):
        merged_map[i] = sorted(merged_map[i].items(), key=lambda kv: kv[1], reverse=True)

    return merged_map