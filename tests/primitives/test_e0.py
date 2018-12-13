from samson.stream_ciphers.e0 import E0
from samson.utilities.bytes import Bytes
import unittest


# Test vectors stripped from the 1999 Bluetooth specification.
# They can be found starting on page 905 in the 'Sample Data' -> 'Encryption Sample Data' section.
# The numbers used here weren't exactly specified but were computed from the 'Z' column
# under the 'Generating 125 key symbols' header of each sample.
class E0TestCase(unittest.TestCase):
    def _run_test(self, kc, addr, clk, expected_keystream):
        e0 = E0(kc=kc, addr=addr, master_clk=clk)

        # Need to generate 125 bits
        keystream = Bytes(e0.generate(16).int() >> 3)

        self.assertEqual(keystream, expected_keystream)



    def test_vec0(self):
        kc   =  [0x0] * 16
        addr =  [0x0] * 6
        clk  =  [0x0] * 4

        expected_keystream = Bytes(11699092579216089282591249681538806196)

        self._run_test(kc, addr, clk, expected_keystream)



    def test_vec1(self):
        kc   =  [0x0] * 16
        addr =  [0x0] * 6
        clk  =  [0x0, 0x0, 0x0, 0x3]

        expected_keystream = Bytes(23388121180021676302755638581783979721)

        self._run_test(kc, addr, clk, expected_keystream)



    def test_vec2(self):
        kc   =  [0xFF] * 16
        addr =  [0xFF] * 6
        clk  =  [0xFF, 0xFF, 0xFF, 3]

        expected_keystream = Bytes(23261483999514518848468053083690299529)

        self._run_test(kc, addr, clk, expected_keystream)



    def test_vec3(self):
        kc   =  [0x21, 0x87, 0xF0, 0x4A, 0xBA, 0x90, 0x31, 0xD0, 0x78, 0x0D, 0x4C, 0x53, 0xE0, 0x15, 0x3A, 0x63]
        addr =  [0x2C, 0x7F, 0x94, 0x56, 0x0F, 0x1B]
        clk  =  [0x5F, 0x1A, 0x00, 0x02]

        expected_keystream = Bytes(6912219919058467808032227317656105605)

        self._run_test(kc, addr, clk, expected_keystream)
