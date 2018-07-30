#!/usr/bin/python3
import urllib.parse
from samson.utilities import *
from samson.aes_cbc import *
from samson.attacks.cbc_bitflipping_attack import CBCBitflippingAttack
from samson.oracles.cbc_encryption_oracle import CBCEncryptionOracle
import struct
import time


key = gen_rand_key()
iv = gen_rand_key()

def format_data(data):
    return ("comment1=cooking%20MCs;userdata=" + urllib.parse.quote(data) + ";comment2=%20like%20a%20pound%20of%20bacon").encode()


def encrypt_data(data):
    return encrypt_aes_cbc(key, iv, format_data(data))


def login(ciphertext):
    print(decrypt_aes_cbc(key, iv, ciphertext))
    return b';admin=true;' in decrypt_aes_cbc(key, iv, ciphertext)


if __name__ == '__main__':
    # CBC will XOR the bitshift of the edited cipher block
    # with the next blocks. To exploit this structure, we must
    # craft a payload in reverse such that it creates our desired string.
    # To do this, we need a known plaintext and a desired plaintext.
    # We fill the targeted block with the known plaintext.
    # We XOR our desired text, 'hiya;admin=true;', with the plaintext to find the "difference".
    # Finally, we XOR the difference with the original cipher block.

    # comment1=cooking
    # %20MCs;userdata=
    # aaaaaaaaaaaaaaaa
    # ;comment2=%20lik
    # e%20a%20pound%20
    # of%20baconPPPPPP

    oracle = CBCEncryptionOracle(encrypt_data)
    attack = CBCBitflippingAttack(oracle)
    forged_request = attack.execute(b'hiya;admin=true;')

    if(login(bytes(forged_request))):
        print('Success! We\'re admin!')