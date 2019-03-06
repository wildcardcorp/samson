from samson.block_ciphers.des import DES
from samson.utilities.bytes import Bytes
import codecs
import unittest


class DESTestCase(unittest.TestCase):
    # Ensures the cipher always outputs its block size
    def test_zfill(self):
        des = DES(Bytes(0x8000000000000000))
        plaintext = Bytes(b'').zfill(8)
        ciphertext1 = des.encrypt(plaintext)
        ciphertext2 = des.decrypt(plaintext)

        self.assertEqual(des.decrypt(ciphertext1), plaintext)
        self.assertEqual(des.encrypt(ciphertext2), plaintext)


    def _run_test(self, key, plaintext, test_vector):
        des = DES(key)
        ciphertext = des.encrypt(plaintext)

        self.assertEqual(codecs.encode(ciphertext, 'hex_codec'), test_vector)
        self.assertEqual(plaintext, des.decrypt(ciphertext))


    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Des-64-64.test-vectors
    def test_vec1_1(self):
        key = int.to_bytes(0x8000000000000000, 8, 'big')
        plaintext = b'\x00' * 8
        test_vector = b'95A8D72813DAA94D'.lower()

        self._run_test(key, plaintext, test_vector)


    def test_vec1_19(self):
        key = int.to_bytes(0x0000100000000000, 8, 'big')
        plaintext = b'\x00' * 8
        test_vector = b'CE7A24F350E280B6'.lower()

        self._run_test(key, plaintext, test_vector)



    def test_vec2_0(self):
        key = int.to_bytes(0x0000000000000000, 8, 'big')
        plaintext = b'\x80' + b'\x00' * 7
        test_vector = b'95F8A5E5DD31D900'.lower()

        self._run_test(key, plaintext, test_vector)



    def test_vec3_1(self):
        key = int.to_bytes(0x0101010101010101, 8, 'big')
        plaintext = b'\x01' * 8
        test_vector = b'994D4DC157B96C52'.lower()

        self._run_test(key, plaintext, test_vector)


    def test_vec8_0(self):
        key = int.to_bytes(0x0001020304050607, 8, 'big')
        plaintext = int.to_bytes(0x41AD068548809D02, 8, 'big')
        test_vector = b'0011223344556677'.lower()

        self._run_test(key, plaintext, test_vector)
