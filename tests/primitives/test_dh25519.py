from samson.protocols.dh25519 import DH25519
from samson.math.algebra.curves.named import Curve25519, Curve448
from samson.utilities.bytes import Bytes
import unittest

class DH25519TestCase(unittest.TestCase):
    def _run_test(self, curve, key_a, key_b, expected_pub_a=None, expected_pub_b=None, expected_shared_key=None):
        dh_a = DH25519(d=key_a, curve=curve)
        dh_b = DH25519(d=key_b, curve=curve)

        pub_a = dh_a.pub
        pub_b = dh_b.pub

        self.assertEqual(dh_a.derive_key(pub_b), dh_b.derive_key(pub_a))

        if expected_pub_a:
            self.assertEqual(expected_pub_a, int(pub_a.x))
            self.assertEqual(expected_pub_b, int(pub_b.x))

        if expected_shared_key:
            self.assertEqual(dh_a.derive_key(pub_b), expected_shared_key)


    # Let's just test a bunch of random numbers
    def test_gauntlet(self):
        for _ in range(50):
            self._run_test(Curve25519, Bytes.random(32).int(), Bytes.random(32).int())

        for _ in range(50):
            self._run_test(Curve448, Bytes.random(56).int(), Bytes.random(56).int())


    # Actual RFC test vectors https://tools.ietf.org/html/rfc7748#section-5.2
    def test_vec0(self):
        key_a = Bytes(0x77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A)[::-1].int()
        key_b = Bytes(0x5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB)[::-1].int()

        expected_pub_a = Bytes(0x8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A)[::-1].int()
        expected_pub_b = Bytes(0xDE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F)[::-1].int()
        expected_shared_key = Bytes(0x4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742)[::-1]

        self._run_test(Curve25519, key_a, key_b, expected_pub_a, expected_pub_b, expected_shared_key)


    def test_vec1(self):
        key_a = Bytes(0x9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BAF574A9419744897391006382A6F127AB1D9AC2D8C0A598726B)[::-1].int()
        key_b = Bytes(0x1C306A7AC2A0E2E0990B294470CBA339E6453772B075811D8FAD0D1D6927C120BB5EE8972B0D3E21374C9C921B09D1B0366F10B65173992D)[::-1].int()

        expected_pub_a = Bytes(0x9B08F7CC31B7E3E67D22D5AEA121074A273BD2B83DE09C63FAA73D2C22C5D9BBC836647241D953D40C5B12DA88120D53177F80E532C41FA0)[::-1].int()
        expected_pub_b = Bytes(0x3EB7A829B0CD20F5BCFC0B599B6FECCF6DA4627107BDB0D4F345B43027D8B972FC3E34FB4232A13CA706DCB57AEC3DAE07BDC1C67BF33609)[::-1].int()
        expected_shared_key = Bytes(0x07FFF4181AC6CC95EC1C16A94A0F74D12DA232CE40A77552281D282BB60C0B56FD2464C335543936521C24403085D59A449A5037514A879D)[::-1]

        self._run_test(Curve448, key_a, key_b, expected_pub_a, expected_pub_b, expected_shared_key)
