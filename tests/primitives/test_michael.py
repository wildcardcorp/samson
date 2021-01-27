from samson.macs.michael import Michael
from samson.utilities.bytes import Bytes
import unittest

keys = [
    0x82925c1ca1d130b8,
    0x434721ca40639b3f,
    0xe8f9becae97e5d29,
    0x90038fc6cf13c1db,
    0xd55e100510128986,
    0xcde683929b973b7b,
    0xd8959a97d7e08f52,
    0xc4c612a754da5aad
]

class MichaelTestCase(unittest.TestCase):
    def test_vecs(self):
        michael = Bytes(b'Michael')
        last_k  = Bytes(0x0000000000000000)
        for i in range(len(michael)+1):
            m      = Michael(last_k)
            pt     = michael[:i]
            last_k = m.generate(pt)
            self.assertEqual(last_k, Bytes(keys[i]).change_byteorder('little'))


    def test_ieee_vec(self):
        k   = Bytes(0xd55e100510128986)
        pt  = Bytes(0xaaaa0300000008004500004e661a00008011be640a0001220affffff00890089003a000080a601100001000000000000204543454a454845434643455046454549454646434341434143414341434141410000200001)
        mic = Michael(k).generate(pt)

        self.assertEqual(mic, Bytes(0x312d0ffb8cd65830).change_byteorder('little'))
        self.assertEqual(Michael.crack(pt, mic).key, k)
