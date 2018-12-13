#!/usr/bin/python3
from samson.utilities.general import rand_bytes
from samson.hashes.sha1 import SHA1
import unittest

key = rand_bytes()


def insecure_hmac(key, data):
    return SHA1().hash(key + data)


class HMACForgeryTestCase(unittest.TestCase):
    def test_forgery_attack(self):
        message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
        original = insecure_hmac(key, message)
        forged_append = b';admin=true'

        actual_secret_len = -1
        crafted_payload = None
        new_signature = None

        sha1 = SHA1()

        for secret_len in range(64):
            # We attempt a forgery
            # payload, signature = attack.execute(original, message, forged_append, secret_len)
            payload, signature = sha1.length_extension(original, message, forged_append, secret_len)

            # Server calculates HMAC with secret
            desired = insecure_hmac(key, payload)

            if signature == desired:
                actual_secret_len = secret_len
                crafted_payload = payload
                new_signature = signature
                break

        self.assertEqual(actual_secret_len, len(key))
        self.assertEqual(insecure_hmac(key, crafted_payload), new_signature)
