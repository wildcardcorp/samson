from samson.utilities.ecc import Curve25519, Curve448
from samson.utilities.bytes import Bytes
import unittest

class ECCTestCase(unittest.TestCase):
    def _run_test(self, curve, iterations, expected_result):
        k = curve.U
        clamped_k, u = curve.clamp_to_curve(k), curve.U
        for _ in range(iterations):
            k, u = clamped_k * u, k
            clamped_k = curve.clamp_to_curve(k)
        

        self.assertEqual(k, expected_result)



    def test_curve25519_vec1(self):
        self._run_test(Curve25519(), 1, Bytes(0x422C8E7A6227D7BCA1350B3E2BB7279F7897B87BB6854B783C60E80311AE3079)[::-1].int())


    def test_curve25519_vec1000(self):
        self._run_test(Curve25519(), 1000, Bytes(0x684CF59BA83309552800EF566F2F4D3C1C3887C49360E3875F2EB94D99532C51)[::-1].int())
    

    def test_curve448_vec1(self):
        self._run_test(Curve448(), 1, Bytes(0x3F482C8A9F19B01E6C46EE9711D9DC14FD4BF67AF30765C2AE2B846A4D23A8CD0DB897086239492CAF350B51F833868B9BC2B3BCA9CF4113)[::-1].int())


    def test_curve448_vec1000(self):
        self._run_test(Curve448(), 1000, Bytes(0xAA3B4749D55B9DAF1E5B00288826C467274CE3EBBDD5C17B975E09D4AF6C67CF10D087202DB88286E2B79FCEEA3EC353EF54FAA26E219F38)[::-1].int())