#!/usr/bin/python3
# from ch2_11 import gen_rand_key, encryption_oracle
# from ch1_1 import from_base64
# from ch1_7 import encrypt_aes_ecb
# from ch1_8 import get_blocks
# from ch2_9 import pkcs7_unpad
import struct
import base64
from samson.utilities import *
from Crypto.Cipher import AES
from samson.oracles.ecb_encryption_oracle import ECBEncryptionOracle
from samson.attacks.ecb_prepend_attack import ECBPrependAttack

def encrypt_aes_ecb(key, message):
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7_pad(message))


# key = gen_rand_key()
key = b'\x00' * 16
unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'.encode())


def encrypt_rand_ecb(message):
    mod_plain = message + unknown_string
    return encrypt_aes_ecb(key, mod_plain)



attack = ECBPrependAttack(ECBEncryptionOracle(encrypt_rand_ecb))
print(attack.execute())


# def find_block_size(cipher_func):
#     baseline = len(cipher_func(b''))

#     for i in range(33):
#         curr_len = len(cipher_func(('A' * i).encode()))
#         if  curr_len != baseline:
#             return curr_len - baseline


# def oracle_decrypt(cipher_func):
#     baseline = len(cipher_func(b''))
#     print(cipher_func(b''))
#     block_size = find_block_size(cipher_func)
#     print('Blocksize: {}'.format(block_size))

#     if not encryption_oracle(cipher_func(('A' * 256).encode())):
#         # It's ECB!
#         print('AES Mode: ECB')

#         plaintexts = []
#         for curr_block in range(baseline // block_size):
#             plaintext = b''
#             for curr_byte in range(block_size):
#                 if curr_block == 0:
#                     payload = ('A' * (block_size - (curr_byte + 1))).encode()
#                 else:
#                     payload = plaintexts[-1][curr_byte + 1:]

#                 one_byte_short = get_blocks(cipher_func(payload))[curr_block]

#                 for i in range(256):
#                     curr_byte = struct.pack('B', i)
#                     ciphertext = cipher_func(payload + plaintext + curr_byte)

#                     # We're always editing the first block to look like block 'curr_block'
#                     if get_blocks(ciphertext)[0] == one_byte_short:
#                         plaintext += curr_byte
#                         break

#             plaintexts.append(plaintext)
#         return pkcs7_unpad(b''.join(plaintexts))


# if __name__ == '__main__':
#     print(oracle_decrypt(encrypt_rand_ecb))
