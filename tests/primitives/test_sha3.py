from samson.hashes.sha3 import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, cSHAKE128, cSHAKE256
from samson.utilities.bytes import Bytes
import hashlib
import unittest

"""
References:
    https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/cshake_samples.pdf
    https://github.com/Hemoth/cSHAKE/blob/master/cSHAKEPython/test_cSHAKE.py
"""

class SHA3TestCase(unittest.TestCase):
    def test_sha3(self):
        for hash_type, reference_method in [(SHA3_224, hashlib.sha3_224), (SHA3_256, hashlib.sha3_256), (SHA3_384, hashlib.sha3_384), (SHA3_512, hashlib.sha3_512)]:
            sha3 = hash_type()
            for i in range(9):
                for _ in range(100):
                    in_bytes = Bytes.random(i * 32)
                    self.assertEqual(sha3.hash(in_bytes), reference_method(in_bytes).digest())


    def test_shake(self):
        for hash_type, reference_method, length in [(SHAKE128, hashlib.shake_128, 256), (SHAKE256, hashlib.shake_256, 512)]:
            shake = hash_type(length)
            for i in range(9):
                for _ in range(100):
                    in_bytes = Bytes.random(i * 32)
                    self.assertEqual(shake.hash(in_bytes), reference_method(in_bytes).digest(length // 8))



    def test_cshake128_vec0(self):
        c   = cSHAKE128(256, b'', b'Email Signature')
        msg = Bytes(0x00010203).zfill(4)
        kat = Bytes(0xc1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5)
        self.assertEqual(c.hash(msg), kat)


    def test_cshake128_vec1(self):
        c   = cSHAKE128(256, b'', b'Email Signature')
        msg = msg = Bytes(0x000102030405060708090a0b0c0d0E0f101112131415161718191a1b1c1d1E1f202122232425262728292a2b2c2d2E2f303132333435363738393a3b3c3d3E3f404142434445464748494a4b4c4d4E4f505152535455565758595a5b5c5d5E5f606162636465666768696a6b6c6d6E6f707172737475767778797a7b7c7d7E7f808182838485868788898a8b8c8d8E8f909192939495969798999a9b9c9d9E9fa0a1a2a3a4a5a6a7a8a9aaabacadaEafb0b1b2b3b4b5b6b7b8b9babbbcbdbEbfc0c1c2c3c4c5c6c7).zfill(200)
        kat = Bytes(0xc5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b)
        self.assertEqual(c.hash(msg), kat)


    def test_cshake128_vec2(self):
        c   = cSHAKE128(256, b'', b'')
        msg = msg = Bytes()
        kat = Bytes(0x7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26)
        self.assertEqual(c.hash(msg), kat)


    def test_cshake256_vec0(self):
        c   = cSHAKE256(512, b'', b'Email Signature')
        msg = Bytes(0x00010203).zfill(4)
        kat = Bytes(0xd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c)
        self.assertEqual(c.hash(msg), kat)


    def test_cshake256_vec1(self):
        c   = cSHAKE256(512, b'', b'Email Signature')
        msg = msg = msg = Bytes(0x000102030405060708090a0b0c0d0E0f101112131415161718191a1b1c1d1E1f202122232425262728292a2b2c2d2E2f303132333435363738393a3b3c3d3E3f404142434445464748494a4b4c4d4E4f505152535455565758595a5b5c5d5E5f606162636465666768696a6b6c6d6E6f707172737475767778797a7b7c7d7E7f808182838485868788898a8b8c8d8E8f909192939495969798999a9b9c9d9E9fa0a1a2a3a4a5a6a7a8a9aaabacadaEafb0b1b2b3b4b5b6b7b8b9babbbcbdbEbfc0c1c2c3c4c5c6c7).zfill(200)
        kat = Bytes(0x07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb)
        self.assertEqual(c.hash(msg), kat)


    def test_cshake256_vec2(self):
        c   = cSHAKE256(512, b'', b'')
        msg = Bytes()
        kat = Bytes(0x46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be)
        self.assertEqual(c.hash(msg), kat)
