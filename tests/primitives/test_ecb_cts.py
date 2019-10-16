from samson.block_ciphers.modes.ecb_cts import ECBCTS
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.blowfish import Blowfish
from samson.utilities.bytes import Bytes
import unittest

class ECBCTSTestCase(unittest.TestCase):
    def test_gauntlet(self):
        rij = Rijndael(Bytes(0x0).zfill(32))
        cts = ECBCTS(rij)

        for _ in range(100):
            plaintext = Bytes.random(Bytes.random(1).int() + 17)

            if len(plaintext) < 17:
                plaintext = plaintext.zfill(17)

            ciphertext = cts.encrypt(plaintext)
            self.assertEqual(cts.decrypt(ciphertext), plaintext)



    # Vectors manually generated using https://github.com/jashandeep-sohi/python-blowfish
    # NOTE: python-blowfish uses conditional ciphertext-stealing, so plaintext sizes multiple
    # of the block size will be different. We don't test those here.
    def _run_test(self, key, plaintext, expected_ciphertext):
        bf = Blowfish(key)
        cts = ECBCTS(bf)

        ciphertext = cts.encrypt(plaintext)
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(cts.decrypt(ciphertext), plaintext)



    def test_vec0(self):
        key                 = Bytes(b'\x0cW\\\xfbn\x04\x10:\xfe\n\x00\x16\xc0T\x0f\xeb')
        plaintext           = Bytes(b'Q\xe6wX\x1eF\xe8],')
        expected_ciphertext = Bytes(b'6\x0e*\xad\x92\xdd\xd2J\x82')

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec1(self):
        key                 = Bytes(b'\x1a\xe4\x95\x1c\xb9.\x96i\x86c\xe9ziQ\th')
        plaintext           = Bytes(b'`d\xde&u\x1b\xad4NJ')
        expected_ciphertext = Bytes(b'\xf7ko\xc7\xf7\x15\xca\x17\x12\xc9')

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec2(self):
        key                 = Bytes(b'\xf0n\x81\xd6\xeb\xfb\x11\xf4\xe1\xfcG!u#J\x9a')
        plaintext           = Bytes(b'\x82\xefq\x8d\xbd\xf0\xc66w\x19\xf3')
        expected_ciphertext = Bytes(b'GHWu\xbe\xcaM\x19\xefw\xb0')

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec3(self):
        key                 = Bytes(b'\x17\x95\x94\xc1\x16\xa3\xf6\x9a\x05\xcd\xc6\xa8\xe0\xf5}\x8a')
        plaintext           = Bytes(b'\x9a\x07x\xe4_%\xae\xf6\xc0E\xa2c')
        expected_ciphertext = Bytes(b'\x84\x92\x0b\xca\xdb\xc30\\\xdf\xdbW\xf4')

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec4(self):
        key                 = Bytes(b'\xabc\x99&y\x0bG\xedd\x0c6\r\x9b\\\xc8Y')
        plaintext           = Bytes(b'\xe6\x80\x83\xe2\xd5\xb2)\xe6\xf8\x9c\x18\xb2\xd5')
        expected_ciphertext = Bytes(b'\xd8N\xbf\xdd\x07H^^a\xc5\xb3\xb9\xba')

        self._run_test(key, plaintext, expected_ciphertext)



    def test_vec5(self):
        key                 = Bytes(b'\xe8\x0c\xa9\xdd\x19Z9u\xa3\x8ae]\xcbY.Y')
        plaintext           = Bytes(b'\x85; e\x03^\xd0.wz\xda?n\xfc')
        expected_ciphertext = Bytes(b'\x00\x19"\x0f\xd2\x9a\xca\xeb\xe7\x12\x95!\xacf')

        self._run_test(key, plaintext, expected_ciphertext)


    def test_vec6(self):
        key                 = Bytes(b'\xb5\x97\t\xc9\xa2\x89\xd5\xfa>\x06\x17\xd6\x07}\x8e\xdb')
        plaintext           = Bytes(b'Y-\x07\x8f\xe6\xa4\xf7\xc7\xda[\xc74\x17iK')
        expected_ciphertext = Bytes(b'\x99\xee\x07w\x86\x87\x97\x8f\xe5@*\x1d$<\x8a')

        self._run_test(key, plaintext, expected_ciphertext)
