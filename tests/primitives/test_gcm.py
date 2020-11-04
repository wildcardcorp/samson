from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.gcm import GCM
import codecs
import unittest


# AES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST_VECS = [
    "AES-128-GCM:00000000000000000000000000000000:000000000000000000000000::::58e2fccefa7e3061367f1d57a4e7455a",
    "AES-128-GCM:00000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78::ab6e47d42cec13bdf53a67b21257bddf",
    "AES-128-GCM:feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985::4d5c2af327cd64a62cf35abd2ba6fab4",
    "AES-128-GCM:feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091:feedfacedeadbeeffeedfacedeadbeefabaddad2:5bc94fbc3221a5db94fae95ae7121a47",
    "AES-128-GCM:feffe9928665731c6d6a8f9467308308:cafebabefacedbad:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598:feedfacedeadbeeffeedfacedeadbeefabaddad2:3612d2e79e3b0785561be14aaca2fccb",
    "AES-128-GCM:feffe9928665731c6d6a8f9467308308:9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5:feedfacedeadbeeffeedfacedeadbeefabaddad2:619cc5aefffe0bfa462af43c1699d050",
    "AES-256-GCM:0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000::::530f8afbc74536b9a963b4f1c4cb738b",
    "AES-256-GCM:0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:cea7403d4d606b6e074ec5d3baf39d18::d0d1c8a799996bf0265b98b5d48ab919",
    "AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad::b094dac5d93471bdec1a502270e3cc6c",
    "AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662:feedfacedeadbeeffeedfacedeadbeefabaddad2:76fc6ece0f4e1768cddf8853bb2d551b",
    "AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbad:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f:feedfacedeadbeeffeedfacedeadbeefabaddad2:3a337dbf46a792c45e454913fe2ea8f2",
    "AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f:feedfacedeadbeeffeedfacedeadbeefabaddad2:a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
]


class GCMTestCase(unittest.TestCase):
    # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    # https://boringssl.googlesource.com/boringssl/+/2214/crypto/cipher/cipher_test.txt
    # http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
    def test_all_vecs(self):
        for unparsed_vec in TEST_VECS:
            _alg, key, nonce, plaintext, ciphertext, data, tag = unparsed_vec.split(":")
            key_bytes, nonce, plaintext, expected_ciphertext, data, expected_tag = [codecs.decode(item.encode('utf-8'), 'hex_codec') for item in [key, nonce, plaintext, ciphertext, data, tag]]

            key = Bytes(key_bytes).zfill(len(key_bytes))
            gcm = GCM(Rijndael(key))
            authed_ct = gcm.encrypt(Bytes(nonce), Bytes(plaintext), data)

            self.assertEqual(authed_ct[:-16], expected_ciphertext)
            self.assertEqual(authed_ct[-16:], expected_tag)
            self.assertEqual(plaintext, gcm.decrypt(nonce, authed_ct, data))


    def test_forbidden_attack(self):
        rij  = Rijndael(Bytes.random(32))
        gcm  = GCM(rij)
        nonce = Bytes.random(12)

        ad_a = Bytes.random(8)
        ad_b = Bytes.random(24)

        pt_a = Bytes.random(16)
        pt_b = Bytes.random(16)

        ciphertext_a = gcm.encrypt(plaintext=pt_a, nonce=nonce, data=ad_a)
        ciphertext_b = gcm.encrypt(plaintext=pt_b, nonce=nonce, data=ad_b)

        ciphertext_a, tag_a = ciphertext_a[:-16], ciphertext_a[-16:]
        ciphertext_b, tag_b = ciphertext_b[:-16], ciphertext_b[-16:]

        results = GCM.nonce_reuse_attack(ad_a, ciphertext_a, tag_a, ad_b, ciphertext_b, tag_b)

        self.assertTrue(gcm.H in [res[0] for res in results])
