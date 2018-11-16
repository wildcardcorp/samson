from samson.stream_ciphers.a51 import A51
from samson.utilities.bytes import Bytes
import unittest


class A51TestCase(unittest.TestCase):
    def _run_test(self, key, frame_num, expected_keystream_a, expected_keystream_b):
        a51 = A51(key=key, frame_num=frame_num)
        keystream_a = a51.yield_state(114)
        keystream_b = a51.yield_state(114)

        self.assertEqual(keystream_a, expected_keystream_a)
        self.assertEqual(keystream_b, expected_keystream_b)
    


    def test_vec0(self):
        key = Bytes(0xEFCDAB8967452312)
        frame_num = 0x000134
        keystream_a = Bytes(0x14D3AA960BFA0546ADB861569CA30)
        keystream_b = Bytes(0x093F4D68D757ED949B4CBE41B7C6B)

        self._run_test(key, frame_num, keystream_a, keystream_b)
