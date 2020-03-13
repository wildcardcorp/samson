#!/usr/bin/python3
import urllib.parse
from samson.utilities.general import rand_bytes
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.cbc import CBC
from samson.block_ciphers.modes.ctr import CTR

from samson.attacks.xor_bitflipping_attack import XORBitflippingAttack
from samson.oracles.chosen_plaintext_oracle import ChosenPlaintextOracle
import unittest

key_size = 16
block_size = 16

key = rand_bytes(key_size)
iv = rand_bytes(block_size)
nonce = rand_bytes(block_size // 2)

aes = Rijndael(key)
cbc = CBC(aes, iv)

def format_data(data):
    return ("comment1=cooking%20MCs;userdata=" + urllib.parse.quote(data.decode()) + ";comment2=%20like%20a%20pound%20of%20bacon").encode()


# CBC Functions
def encrypt_data_cbc(data):
    return cbc.encrypt(format_data(data))


def login_cbc(ciphertext):
    print(cbc.decrypt(ciphertext))
    return b';admin=true;' in cbc.decrypt(ciphertext)


# CTR Functions
def encrypt_data_ctr(data):
    return CTR(aes, nonce).encrypt(format_data(data))


def login_ctr(ciphertext):
    return b';admin=true;' in CTR(aes, nonce).encrypt(ciphertext)


class XORBitFlipTestCase(unittest.TestCase):
    def test_bitflip(self):
        oracle = ChosenPlaintextOracle(encrypt_data_cbc)
        attack = XORBitflippingAttack(oracle, block_size=block_size)
        forged_request = attack.execute(b'hiya;admin=true;' * (block_size // 16), 16)

        if(login_cbc(bytes(forged_request))):
            print('Success! We\'re admin!')

        self.assertTrue(login_cbc(bytes(forged_request)))


    def test_ctr_bitflip(self):
        oracle = ChosenPlaintextOracle(encrypt_data_ctr)
        attack = XORBitflippingAttack(oracle, block_size=block_size)
        forged_request = attack.execute(b'hiya;admin=true;' * (block_size // 16), 32)

        if(login_ctr(bytes(forged_request))):
            print('Success! We\'re admin!')

        self.assertTrue(login_ctr(bytes(forged_request)))
