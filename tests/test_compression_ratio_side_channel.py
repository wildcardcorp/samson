#!/usr/bin/python3
import zlib
from samson.primitives.aes_ctr import AES_CTR
from samson.primitives.aes_cbc import encrypt_aes_cbc
from samson.utilities import gen_rand_key
from samson.attacks.compression_ratio_side_channel_attack import CompressionRatioSideChannelAttack
import unittest

block_size = 16

def aes_ctr_oracle(message):
    ciphertext = AES_CTR(gen_rand_key(block_size), gen_rand_key(block_size // 2)).encrypt(zlib.compress(message))
    return len(ciphertext)


def aes_cbc_oracle(message):
    ciphertext = encrypt_aes_cbc(gen_rand_key(block_size), gen_rand_key(block_size), zlib.compress(message), block_size=block_size)
    return len(ciphertext)


def format_req(message):
    return """
POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {}
{}
""".format(len(message), message).encode()


class CompressionRatioSideChannelTestCase(unittest.TestCase):
    def setUp(self):
        self.request = None

    def test_ctr(self):
        self.request = lambda msg: aes_ctr_oracle(format_req(msg))
        self._execute()

    
    def test_cbc(self):
        self.request = lambda msg: aes_cbc_oracle(format_req(msg))
        self._execute()


    def _execute(self):
        secret = b'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
        known_plaintext = b'Cookie: '
        self.request = lambda msg: aes_cbc_oracle(format_req(msg))
        attack = CompressionRatioSideChannelAttack(self, block_size=block_size)

        recovered_plaintext = attack.execute(known_plaintext, len(secret))
        print(recovered_plaintext)
        self.assertEqual(recovered_plaintext, secret)