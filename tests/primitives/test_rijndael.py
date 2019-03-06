from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import codecs
import unittest


class RijndaelTestCase(unittest.TestCase):
     # Ensures the cipher always outputs its block size
    def test_zfill(self):
        cipher_obj = Rijndael(Bytes(0x8000000000000000).zfill(16))
        plaintext = Bytes(b'').zfill(16)
        ciphertext1 = cipher_obj.encrypt(plaintext)
        ciphertext2 = cipher_obj.decrypt(plaintext)

        self.assertEqual(cipher_obj.decrypt(ciphertext1), plaintext)
        self.assertEqual(cipher_obj.encrypt(ciphertext2), plaintext)


    def _run_test(self, key, plaintext, block_size, test_vector, iterations=1):
        rijndael = Rijndael(key, block_size=block_size)

        to_enc = plaintext
        for _ in range(iterations):
            to_enc = rijndael.encrypt(to_enc)

        cipherhex = codecs.encode(to_enc, 'hex_codec')
        self.assertEqual(cipherhex, test_vector)

        to_dec = to_enc
        for _ in range(iterations):
            to_dec = rijndael.decrypt(to_dec)

        self.assertEqual(plaintext, to_dec)


    # AES FIPS tests
    # https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
    def test_k128_b128(self):
        key = int.to_bytes(0x000102030405060708090a0b0c0d0e0f, 16, 'big')
        plaintext = int.to_bytes(0x00112233445566778899aabbccddeeff, 16, 'big')
        test_vector = b'69c4e0d86a7b0430d8cdb78070b4c55a'
        block_size = 16

        self._run_test(key, plaintext, block_size, test_vector)



    def test_k192_b128(self):
        key = int.to_bytes(0x000102030405060708090a0b0c0d0e0f1011121314151617, 24, 'big')
        plaintext = int.to_bytes(0x00112233445566778899aabbccddeeff, 16, 'big')
        test_vector = b'dda97ca4864cdfe06eaf70a0ec0d7191'
        block_size = 16

        self._run_test(key, plaintext, block_size, test_vector)



    def test_k256_b128(self):
        key = int.to_bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f, 32, 'big')
        plaintext = int.to_bytes(0x00112233445566778899aabbccddeeff, 16, 'big')
        test_vector = b'8ea2b7ca516745bfeafc49904b496089'
        block_size = 16

        self._run_test(key, plaintext, block_size, test_vector)



    # Unverified Rijndael Tests
    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-192.unverified.test-vectors
    def test_k256_b192(self):
        key = int.to_bytes(0x8000000000000000000000000000000000000000000000000000000000000000, 32, 'big')
        plaintext = b'\x00' * 24
        test_vector = b'06EB844DEC23F29F029BE85FDCE578CEC5C663CE0C70403C'.lower()
        block_size = 24

        self._run_test(key, plaintext, block_size, test_vector)

        test_vector = b'3E5ECCD1EC6B225E4AF1992BCCA9253BD16DA75FFE590545'.lower()
        self._run_test(key, plaintext, block_size, test_vector, 1000)


    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-256.unverified.test-vectors
    def test_k256_b256(self):
        key = int.to_bytes(0x8000000000000000000000000000000000000000000000000000000000000000, 32, 'big')
        plaintext = b'\x00' * 32
        test_vector = b'E62ABCE069837B65309BE4EDA2C0E149FE56C07B7082D3287F592C4A4927A277'.lower()
        block_size = 32

        self._run_test(key, plaintext, block_size, test_vector)

        test_vector = b'16990D2F01F21A61678538BD10F1F231A1DCB8D4E73CDDF6A33B5B5FA2368E14'.lower()
        self._run_test(key, plaintext, block_size, test_vector, 1000)
